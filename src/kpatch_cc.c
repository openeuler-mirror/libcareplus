/******************************************************************************
 * 2021.10.12 - kpatch_cc: Optimize build_multiple() a little bit
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.11 - kpatch: fix code checker warning
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.08 - enhance kpatch_gensrc and kpatch_elf and kpatch_cc code
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
******************************************************************************/

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <limits.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define	MAX_MODIFY_ARGS	32

/*
The ``kpcc`` internals are pretty simple but somehow confusing, because the aim
was to keep the code as small as possible. The ``kpcc`` resembles the
``ccache`` code. Since ``kpcc`` only handles one action per run it uses a lot
of global variables.

1. The ``init`` function is called first. It determines the stage of
   ``kpatch``\ ing, parses environment variables, looks for input files and
   derives ``action`` from the arguments.

2. The following ``action``\ s are associated with invoking the real ``gcc``:

-  ``COMPILE_SINGLE`` for a compilation of a single file (``-c`` switch).  -
``COMPILE_ASSEMBLY_SINGLE`` for a compilation of single assembly file (``-c``
switch with ``.s`` input file).  -  ``COMPILE_ASSEMBLY_CPP_SINGLE`` for a
compilation of a preprocessed assembly file (``-c`` switch with ``.S`` or
``.sx`` input file).  -  ``GENERATE_ASSEMBLY_SINGLE`` for a generation of an
assembly file from the C-language source files (``-S`` switch).  -
``BUILD_MULTIPLE`` for building an output object file from multiple input files
(no switches, multiple input files).

1. The ``emulate_cc`` function after everything is initialized. If the
   ``action`` is to ``PASSTHROUGH`` the invokation (that is, no input files
   were found or stage is ``configure``) it just executes whatever ``KPCCREAL``
   points to and exits.

2. Otherwise, it first modifies args calling ``modify_args``. It removes
   arguments listed by the environment variable ``KPCC_REMOVE_ARGS`` with ``;``
   as a separator, and appends args listed by the environment
   ``KPCC_APPEND_ARGS``.

3. Next, if there is only one input file given, then the ``compile_single`` is
   executed. It executes given action, applying ``kpatch_gensrc`` in debug
   filter mode if necessary by calling the ``do_dbgfilter``. If the
   ``KPATCH_STAGE`` is ``patched``, then the ``kpcc`` first executes
   ``kpatch_gensrc`` in patch-generating mode and feeds its output to the real
   compiler. This is done by ``do_generate_kpatch``.

4. Otherwise, if there is multiple input files given than each of the input
   file's type is checked. Each source input file is processed by the above
   algorithm. Finally, the real gcc is called with the new input files derived
   from the original source files with object files kept in place.

5. After all that, ``kpcc`` frees its resources by calling ``free`` function
   and returns value from the ``emulate_cc``.
*/

static int copy_file(const char *infile, const char *outfile);
static int get_assembler_filename(char *aspath, const char *srcorobjpath);

/* This must be sorted as the bsearch is used against it */
static char *remove_args[MAX_MODIFY_ARGS] = {
	"-g",
};
static int nremove_args = 1;


static char *append_args[MAX_MODIFY_ARGS];
static int nappend_args;


static char *dbgfilter_args[MAX_MODIFY_ARGS] = {
	"--dbg-filter",
	"--dbg-filter-eh-frame",
	"--dbg-filter-gcc-except-table",
	"--os=rhel6"
};
static int ndbgfilter_args = 4;

static char *patch_args[MAX_MODIFY_ARGS] = {
	"--force-gotpcrel",
	"--os=rhel6",
};
static int npatch_args = 2;

static const char *realgcc = "/usr/bin/gcc";

static int kpatch_gensrc_asm = 0;


static enum {
	KPATCH_ORIGINAL,
	KPATCH_PATCHED,
	KPATCH_CONFIGURE
} stage;
static const char *kpatch_stage;


static enum {
	ERROR = 0,
	PASSTHROUGH,
	SHOW_VERSION,
	SHOW_V,
	CPP,
	COMPILE_SINGLE,
	COMPILE_ASSEMBLY_SINGLE,
	COMPILE_ASSEMBLY_CPP_SINGLE,
	GENERATE_ASSEMBLY_SINGLE,
	BUILD_MULTIPLE,
} action = PASSTHROUGH;
static const char *action_name[] = {
	"error",
	"passthrough",
	"show-version",
	"show-v",
	"cpp",
	"compile-single",
	"compile-assembly-single",
	"compile-assembly-cpp-single",
	"generate-assembly-single",
	"build-multiple",
};

static const char *stdin_path = "-";

static int argc;
static const char **argv;
static int argv_allocated;


static int ninput_files;
static const char **input_files;
static int idxinput_file;


static const char *output_file;
static int output_file_allocated;


static int idxaction_arg;
static int idxlang_arg;


static const char *prog_name;

static int debug;

static const char *kpatch_prefix = ".kpatch_";
static const char *kpatch_asm_dir = NULL;
static const char *kpatch_path = NULL;

#define CHECK_ALLOC(ptr) do {				\
	if (ptr == NULL)				\
		kpccfatal("%s\n", strerror(errno));	\
} while (0);

static void kpccfatal(const char *fmt, ...)
	__attribute__((__format__ (__printf__, 1, 0)));

static int split_args(char **split, char *args)
{
	char *tok;
	int i = 0;

	tok = strtok(args, ";");
	while (tok && i < MAX_MODIFY_ARGS) {
		split[i++] = tok;
		tok = strtok(NULL, ";");
	}

	if (tok && i == MAX_MODIFY_ARGS)
		kpccfatal("Too many args modifiers\n");

	return i;
}

enum {
	SRC_FILE,
	ASM_FILE,
	ASM_CPP_FILE,
	OBJ_FILE,
	DEV_NULL,
};

static const char *srcexts[] = {
	/* This list is incomplete */
	"c", "cp", "cpp", "cxx", "c++", "C", "CPP"
};

static int get_file_type(const char *arg)
{
	size_t i;
	const char *ext;

	if (arg[0] == stdin_path[0] && arg[1] == stdin_path[1]) {
		const char *lang = argv[idxlang_arg];
		if (*lang == '-')
			lang += 2;
		if (strcmp(lang, "assembler") == 0)
			return ASM_FILE;
		if (strcmp(lang, "assembler-with-cpp") == 0)
			return ASM_CPP_FILE;
		return SRC_FILE;
	}

	if (!strcmp(arg, "/dev/null"))
		return DEV_NULL;

	ext = strrchr(arg, '.');
	if (ext == NULL)
		return OBJ_FILE;

	ext++;

	/* See Options Controlling the Kind of Output, gcc(1) */
	if (ext[0] == 's' && ext[1] == '\0')
	       return ASM_FILE;

	/* .S or .sx */
	if (ext[0] == 'S' &&
		(ext[1] == '\0' ||
		 (ext[2] == 'x' && ext[3] == '\0')))
		return ASM_CPP_FILE;

	for (i = 0; i < ARRAY_SIZE(srcexts); i++) {
		if (strcmp(ext, srcexts[i]) == 0)
			return SRC_FILE;
	}

	return OBJ_FILE;
}

static void init(int argc_, const char **argv_)
{
	const char *input[argc_];
	char *args;
	int ninput = 0, i;
	const char *realgccenv = "KPCCREAL";

	prog_name = argv_[0];

	if (strcmp(prog_name, "g++") == 0 || strcmp(prog_name, "c++") == 0 ||
	    strcmp(prog_name, "kpcc++") == 0) {
		realgccenv = "KPCXXREAL";
		realgcc = "/usr/bin/g++";
	}

	realgcc = getenv(realgccenv) ?: realgcc;

	kpatch_path = getenv("KPATCH_PATH");
	if (kpatch_path == NULL) {
		kpccfatal("KPATCH_PATH is undefined\n");
	}

	kpatch_stage = getenv("KPATCH_STAGE");
	if (kpatch_stage == NULL)
		kpccfatal("KPATCH_STAGE is undefined\n");

	if (strcmp(kpatch_stage, "original") == 0) {
		stage = KPATCH_ORIGINAL;
	} else if (strcmp(kpatch_stage, "patched") == 0) {
		stage = KPATCH_PATCHED;
	} else if (strcmp(kpatch_stage, "configure") == 0) {
		stage = KPATCH_CONFIGURE;
	} else {
		kpccfatal("Wrong KPATCH_STAGE: '%s'\n", kpatch_stage);
	}

	for (i = 0; i < argc_; i++) {
		if (strstr(argv_[i], "conftest.") != NULL ||
		    strstr(argv_[i], "qemu-conf") != NULL) {
			stage = KPATCH_CONFIGURE;
			break;
		}
	}

	if (stage == KPATCH_CONFIGURE) {
		argv = argv_;
		argc = argc_;
		return;
	}

	if (getenv("KPCC_DEBUG"))
		debug = atoi(getenv("KPCC_DEBUG"));

	args = getenv("KPCC_REMOVE_ARGS");
	if (args != NULL) {
		nremove_args = split_args(remove_args, args);

		qsort(remove_args, nremove_args, sizeof(char *),
		      (int (*)(const void *, const void *))strcmp);
	}

	args = getenv("KPCC_APPEND_ARGS");
	if (args != NULL) {
		nappend_args = split_args(append_args, args);
	}

	args = getenv("KPCC_DBGFILTER_ARGS");
	if (args != NULL) {
		ndbgfilter_args = split_args(dbgfilter_args, args);
	}

	args = getenv("KPCC_PATCH_ARGS");
	if (args != NULL) {
		npatch_args = split_args(patch_args, args);
	}

	kpatch_gensrc_asm = getenv("KPATCH_GENSRC_ASM") != NULL;


	argc = argc_;
	/* Reserve place for the appened args and -o and its arg */
	argv = malloc(sizeof(*argv) * (argc + 1 + nappend_args + 2));
	CHECK_ALLOC(argv);
	argv_allocated = 1;

	memcpy(argv, argv_, sizeof(*argv) * (argc + 1));
	argv[0] = realgcc;


	kpatch_prefix = getenv("KPATCH_PREFIX") ?: kpatch_prefix;
	kpatch_asm_dir = getenv("KPATCH_ASM_DIR");

	if (argc == 2 && strcmp(argv[1], "-v") == 0)
		action = SHOW_V;

	memset(input, 0, sizeof(input));

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (arg[0] != '-') {
			input[i] = argv[i];
			idxinput_file = i;
			ninput++;
			continue;
		}

		if (arg[1] == '\0') {
			input[i] = stdin_path;
			idxinput_file = i;
			ninput++;
			continue;
		}


		switch (arg[1]) {
		case 'I':
			if (arg[2] == '\0')
				i++;
			continue;
		case 'x':
			if (arg[2] == '\0')
				i++;
			idxlang_arg = i;
			continue;
		case 'c':
			action = COMPILE_SINGLE;
			idxaction_arg = i;
			continue;
		case 'S':
			action = GENERATE_ASSEMBLY_SINGLE;
			idxaction_arg = i;
			continue;
		case 'E':
			action = CPP;
			continue;
		case 'o':
			if (arg[2] == '\0') {
				argv[i] = NULL;
				output_file = argv[++i];
			} else {
				output_file = arg + 2;
			}
			argv[i] = NULL;
			continue;
		case 'M':
			if (arg[2] == 'F' || arg[2] == 'T' || arg[2] == 'Q')
				i++;
			continue;
		case 'i':
			if (strcmp(arg + 2, "nclude") == 0)
				i++;
			if (strcmp(arg + 2, "system") == 0)
				i++;
			if (strcmp(arg + 2, "quote") == 0)
				i++;
			continue;
		case 'e':
		case 'T':
			i++;
			continue;
		case '-':
			if (strcmp(arg + 2, "version") == 0) {
				action = SHOW_VERSION;
			}
			continue;
		}
	}

	if (ninput > 1 &&
	    (action == COMPILE_SINGLE || action == GENERATE_ASSEMBLY_SINGLE))
		action = ERROR;

	if (ninput && action == PASSTHROUGH)
		action = BUILD_MULTIPLE;

	if (action == ERROR || action == SHOW_VERSION || action == SHOW_V ||
	    action == CPP)
		action = PASSTHROUGH;

	if (action == BUILD_MULTIPLE) {
		input_files = malloc(sizeof(*input_files) * argc);
		CHECK_ALLOC(input_files);

		memcpy(input_files, input, sizeof(*input_files) * argc);

		ninput_files = ninput;
	}

	if ((action == COMPILE_SINGLE || action == GENERATE_ASSEMBLY_SINGLE)
	    && output_file == NULL && input[idxinput_file] != stdin_path) {
		char *ofile = (char *)basename((char *)argv[idxinput_file]);

		if (ofile == NULL) {
			fprintf(stderr, "ofile is null!\n");
			exit(EXIT_FAILURE);
		}
		ofile = strdup(ofile);
		CHECK_ALLOC(ofile);

		output_file_allocated = 1;

		ofile[strlen(ofile) - 1] = action == COMPILE_SINGLE ? 'o' : 's';
		output_file = ofile;
	}

	/* We have failed to estimate the output file, passthrough */
	if (output_file == NULL) {
		fprintf(stderr, "KPCC: can't find output file, passing through\n");
		action = PASSTHROUGH;
	}

	if (output_file && !strcmp(output_file, "/dev/null"))
		action = PASSTHROUGH;

	if (action == COMPILE_SINGLE) {
		switch (get_file_type(argv[idxinput_file])) {
		case ASM_FILE:
			action = COMPILE_ASSEMBLY_SINGLE;
			break;
		case ASM_CPP_FILE:
			action = COMPILE_ASSEMBLY_CPP_SINGLE;
			break;
		case DEV_NULL:
			/*
			 * If the input is /dev/null just passthrough the call
			 */
			action = PASSTHROUGH;
			break;
		}
	}

	if (!kpatch_gensrc_asm &&
	    (action == COMPILE_ASSEMBLY_SINGLE || action == COMPILE_ASSEMBLY_CPP_SINGLE))
		action = PASSTHROUGH;

	if (action == PASSTHROUGH) {
		argc = argc_;

		argv_[0] = argv[0];
		free(argv);
		argv_allocated = 0;
		argv = argv_;
	}

#define	PRINT_LIST(arg, varname)	do {				\
	int i;								\
	if (n##arg == 0)						\
		break;							\
	fprintf(stderr, "%s=\"", varname);				\
	for (i = 0; i < n##arg; i++) {					\
		if (arg[i] == NULL)					\
			continue;					\
		fprintf(stderr, "%s", arg[i]);				\
		if (i != n##arg - 1) {					\
			fprintf(stderr, ";");				\
		}							\
	}								\
	fprintf(stderr, "\"\n");					\
} while (0);

	if (debug) {

		if (debug > 1) {
			int i;
			fprintf(stderr, "Ran as \"%s\"", argv_[0]);
			for (i = 1; i < argc; i++) {
				fprintf(stderr, " \"%s\"", argv_[i]);
			}
			fprintf(stderr, "\n");
		}

		fprintf(stderr, "KPCC_DEBUG=%d # debug output enabled\n", debug);
		fprintf(stderr, "KPATCH_STAGE=\"%s\"\n", kpatch_stage);
		fprintf(stderr, "KPCCREAL=\"%s\"\n", realgcc);
		fprintf(stderr, "KPATCH_PREFIX=\"%s\"\n", kpatch_prefix);
		if (kpatch_gensrc_asm)
			fprintf(stderr, "KPATCH_GENSRC_ASM=\"1\"\n");
		fprintf(stderr, "KPATCH_ASM_DIR=\"%s\"\n", kpatch_asm_dir);
		fprintf(stderr, "# action is %s\n", action_name[action]);
		fprintf(stderr, "# %d input files: \n", ninput);
		for (i = 0; i < argc; i++) {
			if (input[i] == NULL)
				continue;
			fprintf(stderr, "# input[%d] = \"%s\"\n", i, input[i]);
		}
		PRINT_LIST(remove_args, "KPCC_REMOVE_ARGS");
		PRINT_LIST(append_args, "KPCC_APPEND_ARGS");
		PRINT_LIST(dbgfilter_args, "KPCC_DBGFILTER_ARGS");
		PRINT_LIST(patch_args, "KPCC_PATCH_ARGS");
	}
}

static void fini(void)
{
	if (input_files != NULL) {
		free(input_files);
		input_files = NULL;
	}

	if (argv_allocated) {
		free(argv);
		argv = NULL;
		argv_allocated = 1;
	}

	if (output_file_allocated) {
		free((void *)output_file);
		output_file = NULL;
		output_file_allocated = 0;
	}
}

static int bsearch_strcmp(const void *_a, const void *_b)
{
	const char *a = _a;
	const char *b = *(const char **)_b;

	return strcmp(a, b);
}

static int modify_args(void)
{
	int i, j;

	/* Nullify args that are to be removed */
	for (i = 1; i < argc; i++) {
		const char **found;
		if (argv[i] == NULL || argv[i][0] != '-' || argv[i][1] == '\0')
			continue;

		found = bsearch(argv[i], remove_args, nremove_args,
				sizeof (char *),
				bsearch_strcmp);

		if (found != NULL)
			argv[i] = NULL;
	}

	/* Filter out all NULL args */
	i = j = 1;
	while (i < argc && j < argc) {
		if (argv[j] == NULL) {
			j++;
			continue;
		}

		if (i != j) {
			argv[i] = argv[j];

			if (input_files) {
				input_files[i] = input_files[j];
				input_files[j] = NULL;
			}

			if (idxaction_arg == j)
				idxaction_arg = i;
			if (idxinput_file == j)
				idxinput_file = i;
			if (idxlang_arg == j)
				idxlang_arg = i;
		}

		i++;
		j++;
	}
	argc = i;
	argv[argc] = NULL;


	/* Append args (if any) and fill -o placeholders */
	if (nappend_args) {
		memcpy(argv + argc, append_args, sizeof(*argv) * nappend_args);
		argc += nappend_args;
	}

	argv[argc] = argv[argc + 1] = argv[argc + 2] = NULL;

	return 0;
}

static int run_cmd(const char **argv, const char *path)
{
	pid_t pid;
	int status;

	if (debug) {
		int i = 0;
		fprintf(stderr, "\"%s\"", path ?: argv[0]);
		for (i = 1; argv[i]; i++) {
			fprintf(stderr, " \"%s\"", argv[i]);
		}
		fprintf(stderr, "\n");
	}

	pid = vfork();
	if (pid == 0) {
		execv(path ?: argv[0], (char * const *)argv);
		kpccfatal("execv(%s): %s\n", path ?: argv[0], strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		int rv = waitpid(pid, &status, __WALL);
		if (rv == -1)
			kpccfatal("waitpid(%d): %s\n", pid, strerror(errno));

		return WEXITSTATUS(status);
	}
}

static int run_gensrc(const char **argv)
{
	const int gensrcpathlen = strlen(kpatch_path) + sizeof("/kpatch_gensrc");
	char gensrcpath[gensrcpathlen];

	strcpy(gensrcpath, kpatch_path);
	strcpy(gensrcpath + gensrcpathlen - sizeof("/kpatch_gensrc"),
		"/kpatch_gensrc");

	return run_cmd(argv, gensrcpath);
}

static int do_dbgfilter(const char *aspath)
{
	const int tmpnamelen = strlen(aspath) + sizeof(".tmp");
	char tmpname[tmpnamelen];
	int rv, i;

	const char *gensrc_argv[6 + ndbgfilter_args];

	if (ndbgfilter_args == 0)
		return 0;

	gensrc_argv[0] = "kpatch_gensrc";
	for (i = 0; i < ndbgfilter_args; i++) {
		gensrc_argv[i + 1] = dbgfilter_args[i];
	}

	gensrc_argv[i + 1] = "-i";
	gensrc_argv[i + 2] = aspath;
	gensrc_argv[i + 3] = "-o";
	gensrc_argv[i + 4] = tmpname;
	gensrc_argv[i + 5] = NULL;

	strcpy(tmpname, aspath);
	strcpy(tmpname + tmpnamelen - sizeof(".tmp"), ".tmp");

	rv = run_gensrc(gensrc_argv);
	if (rv)
		return rv;

	if (debug)
		fprintf(stderr, "mv \"%s\" \"%s\"\n",
			tmpname, aspath);
	rv = rename(tmpname, aspath);

	return rv;
}

static int do_generate_kpatch(char *aspath)
{
	const int aspathlen = strlen(aspath) + 1;
	const int tmpnamelen = aspathlen - sizeof(".patched.s")
				+ sizeof(".s.tmp");
	const int orignamelen = aspathlen - sizeof(".patched.s")
				+ sizeof(".original.s");
	char origname[orignamelen];
	char tmpname[tmpnamelen];
	const char *gensrc_argv[8 + npatch_args];
	int i, rv;


	strncpy(origname, aspath, orignamelen);
	strcpy(origname + aspathlen - sizeof(".patched.s"),
	       ".original.s");

	if (access(origname, F_OK) == -1) {
		if (errno == ENOENT) {
			if (debug) {
				fprintf(stderr,
					"original file '%s' not found, using "
					"'/dev/null'\n",
					origname);
			}

			strcpy(origname, "/dev/null");
		} else {
			kpccfatal("can't access origignal file %s: %s\n",
				  origname, strerror(errno));
		}
	} else {
		rv = do_dbgfilter(origname);
		if (rv)
			return rv;
	}

	rv = do_dbgfilter(aspath);
	if (rv)
		return rv;

	strncpy(tmpname, aspath, tmpnamelen);
	strcpy(tmpname + aspathlen - sizeof(".patched.s"),
	       ".s.tmp");

	gensrc_argv[0] = "kpatch_gensrc";
	for (i = 0; i < npatch_args; i++) {
		gensrc_argv[i + 1] = patch_args[i];
	}

	gensrc_argv[i + 1] = "-i";
	gensrc_argv[i + 2] = origname;
	gensrc_argv[i + 3] = "-i";
	gensrc_argv[i + 4] = aspath;
	gensrc_argv[i + 5] = "-o";
	gensrc_argv[i + 6] = tmpname;
	gensrc_argv[i + 7] = NULL;

	rv = run_gensrc(gensrc_argv);
	if (rv)
		return rv;

	strcpy(aspath + aspathlen - sizeof(".patched.s"), ".s");

	if (debug)
		fprintf(stderr, "mv \"%s\" \"%s\"\n",
			tmpname, aspath);

	rv = rename(tmpname, aspath);

	return rv;
}

static int compile_single(int action)
{
	char outarg[PATH_MAX + 16] = "-o", *aspath = outarg + 2;
	int rv;

	switch (action) {
	case COMPILE_ASSEMBLY_CPP_SINGLE:
		argv[idxaction_arg] = "-E";
		break;
	case GENERATE_ASSEMBLY_SINGLE:
		break;
	default:
		argv[idxaction_arg] = "-S";
		break;
	}

	(void) get_assembler_filename(aspath, output_file);

	switch (action) {
	case COMPILE_ASSEMBLY_SINGLE:
		copy_file(argv[idxinput_file], aspath);
		break;
	case COMPILE_ASSEMBLY_CPP_SINGLE:
	case COMPILE_SINGLE:
	case GENERATE_ASSEMBLY_SINGLE:
		argv[argc] = "-o";
		argv[argc + 1] = aspath;

		rv = run_cmd(argv, NULL);
		if (rv != 0)
			return rv;
		break;
	}

	if (stage == KPATCH_PATCHED) {
		rv = do_generate_kpatch(aspath);
		if (rv)
			return rv;
	}

	switch (action) {
	case GENERATE_ASSEMBLY_SINGLE:
		return copy_file(aspath, output_file);
	case COMPILE_ASSEMBLY_CPP_SINGLE:
	case COMPILE_ASSEMBLY_SINGLE:
	case COMPILE_SINGLE:
		argv[idxaction_arg] = "-c";
		argv[idxinput_file] = aspath;

		argv[argc] = "-o";
		argv[argc + 1] = output_file;

		if (idxlang_arg) {
			argv[idxlang_arg] =
				argv[idxlang_arg][0] == '-' ?  "-xassembler"
							    :  "assembler";
		}

		return run_cmd(argv, NULL);
	}

	return 129;
}

static int build_multiple(void)
{
	char aspath[PATH_MAX];
	int i, j, rv;
	int newargc = argc - ninput_files + 1 + 2 + 1 + 1;
	int argnum;
	const char *newargv[newargc];

	i = j = 0;
	while (i < newargc && j < argc) {
		if (input_files[j] != NULL) {
			j++;
			continue;
		}

		newargv[i++] = argv[j++];
	}

	argnum = i;
	if (argnum + 4 >= newargc) {
		kpccfatal("Failed to build multiple due to buffer overflow.\n");
	}

	newargv[argnum + 4] = NULL;

	newargv[argnum + 2] = "-o";
	newargv[argnum + 3] = aspath;

	for (i = 1; i < argc; i++) {
		if (input_files[i] == NULL)
			continue;

		newargv[argnum + 1] = input_files[i];
		(void) get_assembler_filename(aspath, input_files[i]);

		switch (get_file_type(input_files[i])) {
		case OBJ_FILE:
passthrough_file:
			input_files[i] = strdup(input_files[i]);
			continue;
		case ASM_FILE:
			if (!kpatch_gensrc_asm)
				goto passthrough_file;

			copy_file(input_files[i], aspath);
			break;
		case ASM_CPP_FILE:
			if (!kpatch_gensrc_asm)
				goto passthrough_file;

			newargv[argnum + 0] = "-E";
			rv = run_cmd(newargv, NULL);
			if (rv)
				goto out;
			break;
		case SRC_FILE:
			newargv[argnum + 0] = "-S";
			rv = run_cmd(newargv, NULL);
			if (rv)
				goto out;
			break;
		}

		if (stage == KPATCH_PATCHED) {
			rv = do_generate_kpatch(aspath);
			if (rv)
				goto out;
		}

		input_files[i] = strdup(aspath);
	}

	for (i = 1; i < argc; i++) {
		if (input_files[i])
			argv[i] = input_files[i];
	}

	if (output_file != NULL) {
		argv[argc] = "-o";
		argv[argc + 1] = output_file;
	}

	rv = run_cmd(argv, NULL);

out:
	for (j = 1; j < i; j++) {
		if (input_files[j]) {
			free((void *)input_files[j]);
			input_files[j] = NULL;
		}
	}

	return rv;
}

static int emulate_cc(void)
{
	int rv;

	if (action == PASSTHROUGH || stage == KPATCH_CONFIGURE) {
		argv[0] = realgcc;
		execv(argv[0], (char * const *)argv);
		return 129;
	}

	rv = modify_args();
	if (rv != 0)
		action = ERROR;

	switch (action) {
	case COMPILE_SINGLE:
	case COMPILE_ASSEMBLY_SINGLE:
	case COMPILE_ASSEMBLY_CPP_SINGLE:
	case GENERATE_ASSEMBLY_SINGLE:
		rv = compile_single(action);
		break;
	case BUILD_MULTIPLE:
		rv = build_multiple();
		break;
	default:
		rv = 129;
		/* FALLTHROUGH */
	case ERROR:
		break;
	}

	return rv;
}

int main(int argc_, const char **argv_)
{
	int rv;

	init(argc_, argv_);

	rv = emulate_cc();
	fini();

	return rv;
}


/****************************************************************************
 * Utils
 ****************************************************************************/

static int copy_file(const char *infile, const char *outfile)
{
	int fdin, fdout;
	char buffer[4096];
	ssize_t r;

	fdin = open(infile, O_RDONLY);
	if (fdin == -1)
		kpccfatal("can't open '%s': %s\n", infile, strerror(errno));

	(void) unlink(outfile);

	fdout = open(outfile, O_WRONLY|O_CREAT, 0644);
	if (fdout == -1)
		kpccfatal("can't open '%s': %s\n", outfile, strerror(errno));

	while (1) {
		ssize_t w;

		r = read(fdin, buffer, sizeof(buffer));
		if (r == 0)
			break;

		if (r == -1 && errno == EINTR)
			continue;

		if (r == -1)
			kpccfatal("can't read '%s': %s\n",
				  infile, strerror(errno));

		for (w = 0; w < r;) {
			ssize_t c;

			c = write(fdout, buffer + w, r);
			if (c == -1 && errno == EINTR)
				continue;

			if (c == -1)
				kpccfatal("can't write '%s': %s\n",
					  outfile, strerror(errno));

			w += c;
		}
	}

	(void) close(fdin);
	(void) close(fdout);

	if (debug)
		fprintf(stderr, "cp \"%s\" \"%s\"\n", infile, outfile);

	return 0;
}

static void kpccfatal(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);

	fprintf(stderr, "%s: ", prog_name);
	vfprintf(stderr, fmt, va);

	va_end(va);

	fini();

	exit(129);
}

static void make_dirs(char *path)
{
	int rv;
	/* Skip the very first '/' in absolute path */
	char *delim, *p = path + 1;

	while ((delim = strchr(p, '/')) != NULL) {
		*delim = '\0';

		rv = mkdir(path, 0755);
		if (rv == -1 && errno != EEXIST)
			kpccfatal("can't makedir %s: %s\n", path,
				  strerror(errno));

		*delim = '/';
		p = delim + 1;
	}
}

static int get_assembler_filename(char *aspath, const char *srcorobjpath)
{
	char buf[PATH_MAX], *bname, *dname;
	int rv;

	if (srcorobjpath == stdin_path) {
		srcorobjpath = output_file;
	}

	buf[sizeof(buf) - 1] = '\0';
	strncpy(buf, srcorobjpath, sizeof(buf));
	if (buf[sizeof(buf) - 1] != '\0')
		kpccfatal("%s: buffer overflow\n", __func__);

	bname = basename(buf);
	if (bname == buf)
		dname = ".";
	else
		dname = dirname(buf);

	if (kpatch_asm_dir != NULL) {
		dname = realpath(dname, NULL);
		if (dname == NULL)
			kpccfatal("%s: realpath error: %s\n", __func__,
				  strerror(errno));
	}

	rv = snprintf(aspath, PATH_MAX, "%s%s/%s%s.%s.s",
		      kpatch_asm_dir ?: "",
		      dname, kpatch_prefix, bname, kpatch_stage);
	if (rv >= PATH_MAX)
		kpccfatal("%s: buffer overflow\n", __func__);

	if (kpatch_asm_dir != NULL) {
		strcpy(buf, aspath);
		make_dirs(buf);
		free(dname);
	}

	return rv;
}
