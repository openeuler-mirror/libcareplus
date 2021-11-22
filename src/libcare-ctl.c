#include <stdio.h>

#include "include/kpatch_user.h"
#include "include/kpatch_log.h"

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

/* entry point */
int main(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "+vh")) != EOF) {
        switch (opt) {
            case 'v':
                log_level += 1;
                break;
            case 'h':
                return usage(NULL);
            default:
                return usage("unknown option");
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1)
        return usage("not enough arguments.");

    return execute_cmd(argc, argv);
}
