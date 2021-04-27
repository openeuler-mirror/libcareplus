/******************************************************************************
 * 2021.10.12 - misc: fix trivial codex issues and compile warning
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define handle_error(errstr) do { perror(errstr); exit(EXIT_FAILURE); } while (0)

#define DEFAULT_SOCKET	"/var/run/libcare.sock"
#define MAX_BUFLEN	16384

int main(int argc, char **argv)
{
	int sock, rv, buflen, i;
	struct sockaddr_un sockaddr;
	char *buffer = NULL, *p, *sockpath = DEFAULT_SOCKET;

	if (argc < 2 || (argv[1][0] == '/' && argc < 3)) {
		printf("%s: [/SOCKET] ARG0 [ARG1] [ARG2]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	argv++;
	argc--;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		handle_error("socket(AF_UNIX)");

	sockaddr.sun_family = AF_UNIX;

	if (argv[0][0] == '/') {
		sockpath = argv[0];
		argv++;
		argc--;
	}
	strncpy(sockaddr.sun_path, sockpath, sizeof(sockaddr.sun_path) - 1);

	rv = connect(sock, (const struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (rv == -1)
		handle_error("connect");

	buflen = 0;
	for (i = 0; i < argc; i++) {
		buflen += strlen(argv[i]) + 1;
	}
	buflen++;
	if (buflen <= 0 || buflen > MAX_BUFLEN) {
		handle_error("buflen overflow");
	}

	p = buffer = malloc(buflen);
	if (buffer == NULL)
		handle_error("malloc");
	for (i = 0; i < argc; i++) {
		p = stpcpy(p, argv[i]);
		p++;
	}
	*p++ = '\0';

	rv = send(sock, (void *)buffer, buflen, 0);
	if (rv == -1)
		handle_error("send");

	if (buflen < 4096) {
		free(buffer);
		buflen = 4096;
		buffer = malloc(buflen);
		if (buffer == NULL) {
			handle_error("malloc buffer failed");
		}
	}

	while (1) {
		rv = recv(sock, buffer, buflen, 0);
		if (rv == 0)
			break;
		if (rv < 0)
			handle_error("recv");
		if (write(1, buffer, rv) < 0) {
			handle_error("write failed");
		}
	}

	close(sock);
	free(buffer);

	return 0;
}
