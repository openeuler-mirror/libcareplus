#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "include/kpatch_user.h"
#include "include/kpatch_log.h"

/* Server part. Used as a start-up notification listener. */
#define SERVER_STOP    (1<<30)
static char storage_dir[PATH_MAX] = "/var/lib/libcare";

static int
cmd_execve_startup(int fd, int argc, char *argv[], int is_just_started)
{
	int rv, pid;

	rv = sscanf(argv[1], "%d", &pid);
	if (rv != 1) {
		kperr("can't parse pid from %s", argv[1]);
		return -1;
	}

	optind = 1;
	rv = patch_user(storage_dir, pid, is_just_started, fd);

	if (rv < 0)
		kperr("can't patch pid %d\n", pid);

	return 0;
}

	static void
kill_and_wait(int pid)
{
	int status;

	(void) kill(pid, SIGTERM);
	(void) waitpid(pid, &status, 0);
}

static int childpid;

	static int
cmd_run(int argc, char *argv[])
{
	int pid;

	if (childpid) {
		kill_and_wait(childpid);
		childpid = 0;
	}

	pid = fork();
	if (pid == -1) {
		kplogerror("can't fork()\n");
		return -1;
	}

	if (pid == 0) {
		return execl("/bin/sh", "sh", "-c", argv[1], (char *)NULL);
	}

	childpid = pid;
	printf("%d\n", pid);
	return 0;
}

	static int
cmd_kill(int argc, char *argv[])
{
	int pid;

	if (sscanf(argv[1], "%d", &pid) != 1) {
		kperr("can't parse pid from %s\n", argv[1]);
		return -1;
	}

	kpdebug("killing %d\n", pid);
	kill_and_wait(pid);

	return 0;
}

	static int
cmd_storage(int argc, char *argv[])
{
	strncpy(storage_dir, argv[1], PATH_MAX - 1);
	return 0;
}

	static int
cmd_update(int argc, char *argv[])
{
	return patch_user(storage_dir, /* pid */ -1,
			/* is_just_started */ 0,
			/* send_fd */ -1);
}

	static int
server_execute_cmd(int fd, int argc, char *argv[])
{
	char *cmd = argv[0];
	int old_stdout, old_stderr, rv;
	optind = 1;

	if (!strcmp(cmd, "execve"))
		return cmd_execve_startup(fd, argc, argv, 1);
	if (!strcmp(cmd, "startup")) {
		return cmd_execve_startup(fd, argc, argv, 0);
	}
	if (!strcmp(cmd, "update"))
		return cmd_update(argc, argv);
	if (!strcmp(cmd, "storage"))
		return cmd_storage(argc, argv);
	if (!strcmp(cmd, "stop"))
		return SERVER_STOP;

	old_stdout = dup3(1, 101, O_CLOEXEC);
	old_stderr = dup3(2, 102, O_CLOEXEC);

	(void) dup3(fd, 1, O_CLOEXEC);
	(void) dup3(fd, 2, O_CLOEXEC);


	if (!strcmp(cmd, "run"))
		rv = cmd_run(argc, argv);
	else if (!strcmp(cmd, "kill"))
		rv = cmd_kill(argc, argv);
	else
		rv = execute_cmd(argc, argv);

	fflush(stdout);
	fflush(stderr);

	(void) dup2(old_stdout, 1);
	(void) dup2(old_stderr, 2);

	return rv;
}

	static int
handle_client(int fd)
{
	char msg[4096], *argv[32], *p;
	ssize_t off = 0, r;
	int argc;

	do {
		r = recv(fd, msg + off, sizeof(msg) - off, 0);
		if (r == -1 && errno == EINTR)
			continue;

		if (r == 0)
			goto out_close;
		off += r;
	} while (off < sizeof(msg) &&
			(off < 2 ||
			 msg[off - 2] != '\0' ||
			 msg[off - 1] != '\0'));

	if (off == sizeof(msg)) {
		kperr("possible buffer overflow\n");
		goto out_close;
	}

	argv[0] = msg;
	for (p = msg, argc = 1;
			p < msg + off && argc < ARRAY_SIZE(argv);
			p++) {
		if (*p)
			continue;
		p++;

		argv[argc] = p;
		if (*p == '\0')
			break;

		argc++;
	}

	return server_execute_cmd(fd, argc, argv);

out_close:
	close(fd);
	return 0;
}

static int usage_server(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-server <UNIX socket> [STORAGE ROOT]\n");
	return -1;
}

#define LISTEN_BACKLOG 1
	static int
server_bind_socket(const char *path)
{
	int sfd = -1, rv, sockaddr_len;
	struct sockaddr_un sockaddr;

	/* Handle invocation by libcare.service */
	if (path[0] == '&') {
		if (sscanf(path, "&%d", &sfd) == 0)
			return -1;
		return sfd;
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sun_family = AF_UNIX;
	sockaddr_len = strlen(path) + 1;
	if (sockaddr_len >= sizeof(sockaddr.sun_path)) {
		kperr("sockaddr is too long\n");
		return -1;
	}

	strncpy(sockaddr.sun_path, path, sizeof(sockaddr.sun_path));
	if (path[0] == '@')
		sockaddr.sun_path[0] = '\0';

	sockaddr_len += sizeof(sockaddr.sun_family);

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1)
		goto err_close;

	rv = bind(sfd, (struct sockaddr *)&sockaddr,
			sockaddr_len);
	if (rv == -1)
		goto err_close;

	rv = listen(sfd, LISTEN_BACKLOG);
	if (rv == -1)
		goto err_close;

	return sfd;

err_close:
	if (rv < 0)
		kplogerror("can't listen on unix socket %s\n", path);
	if (sfd != -1)
		close(sfd);
	return rv;
}

	static void
kill_child(int signum)
{
	/* Hello Bulba my old friend... */
	(void) signum;
	if (childpid)
		kill_and_wait(childpid);
	exit(0x80 | signum);
}

	static int
cmd_server(int argc, char *argv[])
{
	int sfd = -1, cfd, rv;
	struct sigaction act;

	if (argc < 1)
		return usage_server("UNIX socket argument is missing");

	memset(&act, 0, sizeof(act));
	act.sa_handler = kill_child;
	act.sa_flags = SA_RESTART;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0) {
		kplogerror("can't install signal handler\n");
		return -1;
	}

	sfd = server_bind_socket(argv[0]);
	if (sfd < 0)
		return sfd;

	if (argc >= 2)
		strcpy(storage_dir, argv[1]);

	setlinebuf(stdout);

	while ((cfd = accept4(sfd, NULL, 0, SOCK_CLOEXEC)) >= 0) {
		rv = handle_client(cfd);
		if (rv < 0)
			kplogerror("server error\n");

		(void) close(cfd);
		if (rv == SERVER_STOP)
			break;
	}

	if (childpid)
		kill_and_wait(childpid);

	close(sfd);
	return 0;
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
				return usage_server(NULL);
			default:
				return usage_server("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		return usage_server("not enough arguments.");

	return cmd_server(argc, argv);
}
