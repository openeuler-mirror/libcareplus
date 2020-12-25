/******************************************************************************
 * 2021.10.07 - process: fix region_start caclulation
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com> - 0.1.4-17
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <regex.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include <sys/socket.h>

#include "include/kpatch_process.h"
#include "include/kpatch_file.h"
#include "include/kpatch_common.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_ptrace.h"
#include "include/list.h"
#include "include/kpatch_log.h"

/*
 * Find region for a patch. Take object's `previous_hole` as a left candidate
 * and the next hole as a right candidate. Pace through them until there is
 * enough space in the hole for the patch.
 *
 * Since holes can be much larger than 2GiB take extra caution to allocate
 * patch region inside the (-2GiB, +2GiB) range from the original object.
 */
unsigned long
object_find_patch_region(struct object_file *obj,
			 size_t memsize,
			 struct vm_hole **hole)
{
	struct list_head *head = &obj->proc->vmaholes;
	struct vm_hole *left_hole = obj->previous_hole,
		       *right_hole = next_hole(left_hole, head);
	unsigned long max_distance = 0x8000000;
	struct obj_vm_area *sovma;

	unsigned long obj_start, obj_end;
	unsigned long region_start = 0, region_end = 0;

	kpdebug("Looking for patch region for '%s'...\n", obj->name);

	sovma = list_first_entry(&obj->vma, struct obj_vm_area, list);
	obj_start = sovma->inmem.start;
	sovma = list_entry(obj->vma.prev, struct obj_vm_area, list);
	obj_end = sovma->inmem.end;


	max_distance -= memsize;

	/* TODO carefully check for the holes laying between obj_start and
	 * obj_end, i.e. just after the executable segment of an executable
	 */
	while (left_hole != NULL && right_hole != NULL) {
		if (right_hole != NULL &&
		    right_hole->start - obj_start > max_distance)
			right_hole = NULL;
		else if (hole_size(right_hole) > memsize) {
			region_start = right_hole->start;
			region_end =
				(right_hole->end - obj_start) <= max_distance ?
				right_hole->end - memsize :
				obj_start + max_distance;
			*hole = right_hole;
			break;
		} else
			right_hole = next_hole(right_hole, head);

		if (left_hole != NULL &&
		    obj_end - left_hole->end > max_distance)
			left_hole = NULL;
		else if (hole_size(left_hole) > memsize) {
			region_start =
				(left_hole->start - obj_end) <= max_distance ?
				left_hole->start : obj_end > max_distance    ?
				obj_end - max_distance : 0;
			region_end = left_hole->end - memsize;
			*hole = left_hole;
			break;
		} else
			left_hole = prev_hole(left_hole, head);
	}

	if (region_start == region_end) {
		kperr("can't find suitable region for patch on '%s'\n",
		      obj->name);
		return -1UL;
	}

	region_start = (region_start >> PAGE_SHIFT) << PAGE_SHIFT;
	kpdebug("Found patch region for '%s' at %lx\n", obj->name, region_start);

	return region_start;
}

