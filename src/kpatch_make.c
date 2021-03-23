/******************************************************************************
 * 2021.10.12 - kpatch_make: initialize fd to avoid unexpected close
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 *
 * 2021.10.12 - kpatch: clear code checker warnings
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 *
 * 2021.10.11 - kpatch: clear code checker warnings
 * Huawei Technologies Co., Ltd. <wanghao232@huawei.com>
 *
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

#include "include/kpatch_log.h"
#include "include/kpatch_file.h"

#define ALIGN(x, align)	((x + align - 1) & (~(align - 1)))

static int verbose;

int make_file(int fdo, const void *buf, off_t size,
	      const char *buildid, const char *patch_id)
{
	int res;
	struct kpatch_file khdr;

	memset(&khdr, 0, sizeof(khdr));

	memcpy(khdr.magic, KPATCH_FILE_MAGIC1, sizeof(khdr.magic));
	strncpy(khdr.id, patch_id, sizeof(khdr.id) - 1);
	strncpy(khdr.buildid, buildid, sizeof(khdr.buildid) - 1);
	khdr.build_time = (uint64_t)time(NULL);
	khdr.csum = 0;
	khdr.nr_reloc = 0;

	khdr.rel_offset = sizeof(khdr);
	khdr.kpatch_offset = khdr.rel_offset;
	size = ALIGN(size, 16);
	khdr.total_size = khdr.kpatch_offset + size;

	res = write(fdo, &khdr, sizeof(khdr));
	res += write(fdo, buf, size);

	if (res != sizeof(khdr) + size) {
		kplogerror("write error\n");
		return -1;
	}

	return 0;
}

static void usage(void)
{
	printf("Usage: kpatch_make [-d] -n <modulename> [-v <version>] -e <entryaddr> "
	       "[-o <output>] -i <patch_id> <input1> [input2]\n");
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
	int ret = -1;
	int opt;
	int fd1 = -1;
	int fdo = -1;
	void *buf;
	struct stat st;
	char *buildid = NULL;
	char *outputname = NULL;
	char *patch_id = NULL;

	while ((opt = getopt(argc, argv, "db:o:i:v:s:")) != -1) {
		switch (opt) {
		case 'd':
			verbose = 1;
			break;
		case 'b':
			if (buildid) {
				kplogerror("duplicate inputted buildid\n");
				goto cleanup;
			}
			buildid = strdup(optarg);
			break;
		case 'o':
			if (outputname) {
				kplogerror("duplicate inputted outputname\n");
				goto cleanup;
			}
			outputname = strdup(optarg);
			break;
		case 'i':
			if (patch_id) {
				kplogerror("duplicate inputted patch_id\n");
				goto cleanup;
			}
			patch_id = strdup(optarg);
			break;
		default: /* '?' */
			usage();
		}
	}

	if (verbose)
		log_level = LOG_DEBUG;

	if (buildid == NULL || patch_id == NULL || *patch_id == '\0')
		usage();

	if (strlen(buildid) !=  KPATCH_BUILDID_LEN) {
		kplogerror("Invalid build id: %s", buildid);
	}

	fd1 = open(argv[optind], O_RDONLY);
	if (fd1 == -1) {
		kplogerror("Can't open 1st input file '%s'\n", argv[optind]);
		goto cleanup;
	}

	if (fstat(fd1, &st) == -1) {
		kplogerror("Can't stat file1\n");
		goto cleanup;
	}
	buf = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd1, 0);
	if (buf == MAP_FAILED) {
		kplogerror("mmap error %d", errno);
		goto cleanup;
	}

	fdo = 1;
	if (outputname) {
		fdo = open(outputname, O_CREAT | O_TRUNC | O_WRONLY, 0660);
		if (fdo == -1) {
			kplogerror("Can't open output file '%s'\n", outputname);
			goto unmap;
		}
	}
	ret = make_file(fdo, buf, st.st_size, buildid, patch_id);
unmap:
	munmap(buf, st.st_size);

cleanup:
	close(fdo);
	close(fd1);
	free(buildid);
	free(outputname);
	free(patch_id);
	return ret;
}
