/******************************************************************************
 * 2021.10.12 - libcare-info: rename Process as Target instead
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.07 - libcare-ctl: remove useless codes for info interface
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 *
 * 2021.10.07 - libcare-ctl: optimize output of libcare-ctl info
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 *
 * 2021.09.23 - libcare-ctl: introduce patch-id
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 *
 * 2021.09.23 - libcare-ctl: implement applied patch list
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <regex.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "include/kpatch_user.h"
#include "include/kpatch_storage.h"
#include "include/kpatch_patch.h"
#include "include/kpatch_process.h"
#include "include/kpatch_file.h"
#include "include/kpatch_common.h"
#include "include/kpatch_elf.h"
#include "include/list.h"
#include "include/kpatch_log.h"

/*****************************************************************************
 * Utilities.
 ****************************************************************************/

/* Return -1 to indicate error, -2 to stop immediately */
typedef int (callback_t)(int pid, void *data);

static int
processes_do(int pid, callback_t callback, void *data);


static int
processes_patch(kpatch_storage_t *storage,
		int pid, int is_just_started, int send_fd)
{
	struct patch_data data = {
		.storage = storage,
		.is_just_started = is_just_started,
		.send_fd = send_fd,
	};

	return processes_do(pid, process_patch, &data);
}

/* Check if system is suitable */
static int kpatch_check_system(void)
{
	return 1;
}

static int usage_patch(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl patch [options] <-p PID> <patch>\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "  -p <PID>    - target process\n");
	return err ? 0 : -1;
}

int
patch_user(const char *storage_path, int pid,
	   int is_just_started, int send_fd)
{
	int ret;
	kpatch_storage_t storage;

	ret = storage_init(&storage, storage_path);
	if (ret < 0)
		return ret;

	ret = processes_patch(&storage, pid, is_just_started, send_fd);

	storage_free(&storage);

	return ret;
}


int cmd_patch_user(int argc, char *argv[])
{
	int opt, pid = -1, is_pid_set = 0, ret;
	const char *storage_path;

	if (argc < 4)
		return usage_patch(NULL);

	while ((opt = getopt(argc, argv, "hsp:r:")) != EOF) {
		switch (opt) {
		case 'h':
			return usage_patch(NULL);
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			is_pid_set = 1;
			break;
		default:
			return usage_patch("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (!is_pid_set)
		return usage_patch("PID argument is mandatory");

	if (!kpatch_check_system())
		goto out_err;

	storage_path = argv[argc - 1];

	kpinfo("Applying patch for %d with %s", pid, storage_path);
	ret = patch_user(storage_path, pid,
			 /* is_just_started */ 0, /* send_fd */ -1);

out_err:
	return ret;
}

static int
processes_unpatch(int pid, char *buildids[], int nbuildids, const char *patch_id)
{
	struct unpatch_data data = {
		.buildids = buildids,
		.nbuildids = nbuildids,
		.patch_id = patch_id
	};

	return processes_do(pid, process_unpatch, &data);
}

static int usage_unpatch(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl unpatch [options] <-p PID> <-i patch_id>"
		"[Build-ID or name ...]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h               - this message\n");
	fprintf(stderr, "  -p <PID>         - target process\n");
	fprintf(stderr, "  -i <patch_id>    - target patch id\n");
	return err ? 0 : -1;
}

int cmd_unpatch_user(int argc, char *argv[])
{
	int opt, pid = -1, is_pid_set = 0;
	const char *patch_id = NULL;

	if (argc < 4)
		return usage_unpatch(NULL);

	while ((opt = getopt(argc, argv, "hp:i:")) != EOF) {
		switch (opt) {
		case 'h':
			return usage_unpatch(NULL);
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			is_pid_set = 1;
			break;
		case 'i':
			patch_id = optarg;
			break;
		default:
			return usage_unpatch("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (!is_pid_set || !patch_id)
		return usage_unpatch("PID or patch_id argument is mandatory");

	if (!kpatch_check_system())
		return -1;

	kpinfo("Unpplying patch for %d with patch id '%s'",
	       pid, patch_id);
	return processes_unpatch(pid, argv, argc, patch_id);
}

static int
usage_info(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);

	fprintf(stderr, "usage: libcare-ctl info -p PID\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h		- this message\n");
	fprintf(stderr, "  -p <PID>	- target process, 'all' or omitted for all the system processes\n");
	return err ? 0 : -1;
}

static int
object_info(struct object_file *o)
{
	const char *buildid;
	kpatch_process_t *proc = o->proc;
	struct obj_applied_patch *applied_patch = NULL;

	if (!o->is_elf || is_kernel_object_name(o->name))
		return 0;


	if (!o->num_applied_patch)
		return 0;

	buildid = kpatch_get_buildid(o);
	if (buildid == NULL) {
		kpinfo("can't get buildid for %s\n", o->name);
		return -1;
	}

	printf("%-25s %d\n", "Pid:", proc->pid);
	printf("%-25s %s\n", "Target:", o->name);
	printf("%-25s %s\n", "Build id:", buildid);
	printf("%-25s %ld\n", "Applied patch number:", o->num_applied_patch);
	list_for_each_entry(applied_patch, &o->applied_patch, list) {
		printf("%-25s %s\n", "Patch id:", applied_patch->patch_file->kpfile.patch->id);
	}

	printf("\n");

	return 0;
}

static int
process_info(int pid)
{
	int ret;
	kpatch_process_t _proc, *proc = &_proc;
	struct object_file *o;

	ret = kpatch_process_init(proc, pid, /* start */ 0, /* send_fd */ -1);
	if (ret < 0)
		return -1;

	ret = kpatch_process_mem_open(proc, MEM_READ);
	if (ret < 0)
		goto out;

	ret = kpatch_process_map_object_files(proc, NULL);
	if (ret < 0)
		goto out;


	list_for_each_entry(o, &proc->objs, list) {
		if ((ret = object_info(o)) < 0)
			break;
	}

out:
	kpatch_process_free(proc);
	return ret;
}

int cmd_info_user(int argc, char *argv[])
{
	int opt, pid = -1, verbose = 0;

	 while ((opt = getopt(argc, argv, "hp:v")) != EOF) {
		switch (opt) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			return usage_info(NULL);
		default:
			return usage_info("unknown arg");
		}
	}

	if (!verbose)
		log_level = LOG_ERR;

	kpinfo("Query patch information for %d", pid);
	return process_info(pid);
}

/*****************************************************************************
 * Utilities.
 ****************************************************************************/
static int
processes_do(int pid, callback_t callback, void *data)
{
	DIR *dir;
	struct dirent *de;
	int ret = 0, rv;
	char *tmp, buf[64], buf2[64];

	if (pid != -1)
		return callback(pid, data);

	dir = opendir("/proc");
	if (!dir) {
		kplogerror("can't open '/proc' directory\n");
		return -1;
	}

	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;

		pid = strtoul(de->d_name, &tmp, 10);
		if (pid == 0 || *tmp != '\0')
			continue;

		if (pid == 1 || pid == getpid())
			continue;

		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		rv = readlink(buf, buf2, sizeof(buf2));
		if (rv == -1) {
			if (errno == ENOENT)
				kpdebug("skipping kernel thread %d\n", pid);
			else
				kpdebug("can't get exec for %d: %s\n", pid,
					strerror(errno));
			continue;
		}

		rv = callback(pid, data);
		if (rv < 0)
			ret = -1;
		if (rv == -2)
			break;
	}

	closedir(dir);

	return ret;
}

static int usage(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl [options] <cmd> [args]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -v          - verbose mode\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  patch  - apply patch to a user-space process\n");
	fprintf(stderr, "  unpatch- unapply patch from a user-space process\n");
	fprintf(stderr, "  info   - show info on applied patches\n");
	return -1;
}

int
execute_cmd(int argc, char *argv[])
{
	char *cmd = argv[0];
	optind = 1;

	if (!strcmp(cmd, "patch") || !strcmp(cmd, "patch-user"))
		return cmd_patch_user(argc, argv);
	else if (!strcmp(cmd, "unpatch") || !strcmp(cmd, "unpatch-user"))
		return cmd_unpatch_user(argc, argv);
	else if (!strcmp(cmd, "info") || !strcmp(cmd, "info-user"))
		return cmd_info_user(argc, argv);
	else
		return usage("unknown command");
}
