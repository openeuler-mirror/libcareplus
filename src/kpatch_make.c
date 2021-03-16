/******************************************************************************
 * 2021.10.11 - kpatch: rename uname to buildid
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
 *
 * 2021.10.07 - process: add some checks before patching
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 *
 * 2021.09.23 - libcare-ctl: introduce patch-id
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include "include/kpatch_file.h"

#define ALIGN(x, align)	((x + align - 1) & (~(align - 1)))

static int verbose;

static void xerror(const char *fmt, ...)
{
	va_list va;

        va_start(va, fmt);
        vfprintf(stderr, fmt, va);
        va_end(va);

	exit(1);
}

int make_file(int fdo, void *buf1, off_t size, const char *buildid, const char *patch_id)
{
	int res;
	struct kpatch_file khdr;

	memset(&khdr, 0, sizeof(khdr));

	memcpy(khdr.magic, KPATCH_FILE_MAGIC1, sizeof(khdr.magic));
	strncpy(khdr.id, patch_id, sizeof(khdr.id));
	strncpy(khdr.buildid, buildid, sizeof(khdr.buildid));
	khdr.build_time = (uint64_t)time(NULL);
	khdr.csum = 0;		/* FIXME */
	khdr.nr_reloc = 0;

	khdr.rel_offset = sizeof(khdr);
	khdr.kpatch_offset = khdr.rel_offset;
	size = ALIGN(size, 16);
	khdr.total_size = khdr.kpatch_offset + size;

	res = write(fdo, &khdr, sizeof(khdr));
	res += write(fdo, buf1, size);

	if (res != sizeof(khdr) + size)
		xerror("write error");

	return 0;
}

static void usage(void)
{
	printf("Usage: kpatch_make [-d] -n <modulename> [-v <version>] -e <entryaddr> [-o <output>] -i <patch_id> <input1> [input2]\n");
	printf("   -b buildid = target buildid for patch\n");
	printf("   -d debug (verbose)\n");
	printf("   -i unique patch id\n");
	printf("\n");
	printf("   result is printed to output and is the following:\n");
	printf("      header          - struct kpatch_file\n");
	printf("      .kpatch.*       - sections with binary patch text/data and info\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	int opt;
	int fd1, fdo;
	void *buf;
	struct stat st;
	char *buildid = NULL, *outputname = NULL, *patch_id = NULL;

	while ((opt = getopt(argc, argv, "db:o:i:v:s:")) != -1) {
		switch (opt) {
		case 'd':
			verbose = 1;
			break;
		case 'b':
			buildid = strdup(optarg);
			break;
		case 'o':
			outputname = strdup(optarg);
			break;
		case 'i':
			patch_id = strdup(optarg);
			break;
		default: /* '?' */
			usage();
		}
	}

	if (buildid == NULL || patch_id == NULL || *patch_id == '\0')
		usage();

	if (strlen(buildid) !=  KPATCH_BUILDID_LEN) {
		xerror("Invalid build id: %s", buildid);
	}

	fd1 = open(argv[optind], O_RDONLY);
	if (fd1 == -1)
		xerror("Can't open 1st input file '%s'", argv[optind]);
	if (fstat(fd1, &st) == -1)
		xerror("Can't stat file1");
	buf = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd1, 0);
	if (buf == MAP_FAILED)
		xerror("mmap error %d", errno);
	close(fd1);

	fdo = 1;
	if (outputname) {
		fdo = open(outputname, O_CREAT | O_TRUNC | O_WRONLY, 0660);
		if (fdo == -1)
			xerror("Can't open output file '%s'", outputname);
	}

	return make_file(fdo, buf, st.st_size, buildid, patch_id);
}
