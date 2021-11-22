#ifndef __KPATCH_USER__
#define __KPATCH_USER__

#include "kpatch_common.h"
#include "kpatch_file.h"
#include "rbtree.h"

int cmd_patch_user(int argc, char *argv[]);
int cmd_unpatch_user(int argc, char *argv[]);
int execute_cmd(int argc, char *argv[]);
int patch_user(const char *storage_path, int pid,
			   int is_just_started,
			   int send_fd);
#endif
