/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Description: This is source file of libcare-dump tools.
 *              The libcare-dump tools use like this:
 *                  1. libcare-dump -c -i <input> -o <output>;
 *
 *              For detailed usage, please using: libcare-dump --help.
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include "include/kpatch_file.h"

#define ELFMAG          "\177ELF"
#define SELFMAG         4

void usage()
{
    printf("Usage: libcare-dump -c -i <input> -o <output>\n");
    printf("    -c convert kpatch to elf\n");
    printf("\n");
    printf("    libcare-dump provide some auxiliary tools for help.\n");
    exit(EXIT_FAILURE);
}

int kpatch_convert_to_elf(const char *input_file, const char *output_file)
{
    int fdi = -1;
    int fdo = -1;
    int ret = -1;
    int elf_size;
    struct stat st;
    void *buf = NULL;

    fdi = open(input_file, O_RDONLY);
    if (fdi == -1) {
        printf("Can't open kpatch file '%s'\n", input_file);
        return -1;
    }
    if (fstat(fdi, &st) == -1) {
        printf("Can't stat kpatch file\n");
        goto cleanup;
    }
    /* input kpatch file must bigger than sizeof(struct kpatch_file) */
    elf_size = st.st_size - sizeof(struct kpatch_file);
    if (elf_size <= 0) {
        printf("Invalid kpatch file '%s'\n", input_file);
        goto cleanup;
    }

    buf = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fdi, 0);
    if (buf == MAP_FAILED) {
        printf("Can't map kpatch file\n");
        goto cleanup;
    }

    /* check elf format */
    if (memcmp((void *)(buf + sizeof(struct kpatch_file)),
               ELFMAG, SELFMAG) != 0) {
        printf("check elf format failed\n");
        goto unmap;
    }

    fdo = open(output_file, O_CREAT | O_TRUNC | O_WRONLY, 0550);
    if (fdo == -1) {
        printf("Can't create output file '%s'\n", output_file);
        goto unmap;
    }

    /* write elf to output file */
    if (write(fdo, buf + sizeof(struct kpatch_file), elf_size) != elf_size) {
        printf("Write error\n");
        goto unmap;
    }
    ret = 0;

 unmap:
    munmap(buf, st.st_size);

 cleanup:
    if (fdi > 0) {
        close(fdi);
    }
    if (fdo > 0) {
        close(fdo);
    }
    return ret;
}

int main(int argc, char **argv)
{
    int opt;
    int ret = -1;
    int convert_to_elf = 0;
    char *input_file = NULL;
    char *output_file = NULL;

    if (argc < 6) {
        usage();
    }

    while ((opt = getopt(argc, argv, "i:o:c::")) != -1) {
        switch (opt) {
        case 'i':
            input_file = strdup(optarg);
            break;
        case 'o':
            output_file = strdup(optarg);
            break;
        case 'c':
            convert_to_elf = 1;
            break;
        default:
            free(input_file);
            free(output_file);
            usage();
        }
    }

    if (input_file == NULL || output_file == NULL) {
        free(input_file);
        free(output_file);
        usage();
    }

    if (convert_to_elf) {
        ret = kpatch_convert_to_elf(input_file, output_file);
    }

    free(input_file);
    free(output_file);
    return ret;
}

