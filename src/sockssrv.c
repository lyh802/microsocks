/*
   MicroSocks - multithreaded, small, efficient SOCKS5 server.

   Copyright (C) 2017 rofl0r.

   This is the successor of "rocksocks5", and it was written with
   different goals in mind:

   - prefer usage of standard libc functions over homegrown ones
   - no artificial limits
   - do not aim for minimal binary size, but for minimal source code size,
     and maximal readability, reusability, and extensibility.

   as a result of that, ipv4, dns, and ipv6 is supported out of the box
   and can use the same code, while rocksocks5 has several compile time
   defines to bring down the size of the resulting binary to extreme values
   like 10 KB static linked when only ipv4 support is enabled.

   still, if optimized for size, *this* program when static linked against musl
   libc is not even 50 KB. that's easily usable even on the cheapest routers.

*/

#define _GNU_SOURCE
#include <unistd.h>
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "sblist.h"

#define THREAD_BUFFER_SIZE 2048

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef PTHREAD_STACK_MIN
#define THREAD_STACK_SIZE MAX(8*1024, PTHREAD_STACK_MIN)
#else
#define THREAD_STACK_SIZE 64*1024
#endif

#if defined(__APPLE__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 64*1024
#elif defined(__GLIBC__) || defined(__FreeBSD__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#endif

enum socksstate {
	SS_1_CONNECTED,
	SS_2_NEED_AUTH, /* skipped if NO_AUTH method supported */
	SS_3_AUTHED,
};

enum addresstype {
	AT_IPV4 = 1,
	AT_DNS = 3,
	AT_IPV6 = 4,
};

enum authmethod {
	AM_NO_AUTH = 0,
	AM_GSSAPI = 1,
	AM_USERNAME = 2,
	AM_INVALID = 0xFF,
};

enum errorcode {
	EC_SUCCESS = 0,
	EC_GENERAL_FAILURE = 1,
	EC_NOT_ALLOWED = 2,
	EC_NET_UNREACHABLE = 3,
	EC_HOST_UNREACHABLE = 4,
	EC_CONN_REFUSED = 5,
	EC_TTL_EXPIRED = 6,
	EC_COMMAND_NOT_SUPPORTED = 7,
	EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};

union sockaddr_union {
	struct sockaddr_in  v4;
	struct sockaddr_in6 v6;
};

#define SOCKADDR_UNION_AF(PTR) (PTR)->v6.sin6_family

#define SOCKADDR_UNION_LENGTH(PTR) (\
	(SOCKADDR_UNION_AF(PTR) == AF_INET6) ? sizeof((PTR)->v6) : sizeof((PTR)->v4))

#define SOCKADDR_UNION_ADDRESS(PTR) (struct sockaddr*)(\
	(SOCKADDR_UNION_AF(PTR) == AF_INET6) ? &(PTR)->v6.sin6_addr : &(PTR)->v4.sin_addr)

struct client {
	int fd;
	union sockaddr_union addr;
};

struct thread {
	pthread_t pt;
	volatile int done;
	struct client client;
};

static const char* auth_user = 0;
static const char* auth_pass = 0;
static sblist* auth_ips = 0;
static pthread_rwlock_t auth_ips_lock = PTHREAD_RWLOCK_INITIALIZER;
static union sockaddr_union bind_addr = { .v4.sin_family = AF_UNSPEC, };

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) dprintf(2, __VA_ARGS__)
#else
static void dolog(const char* fmt, ...) { }
#endif

static int connect_socks_target(struct client* client, unsigned char* in, ssize_t n) {
	// 至少6字节
	if (n < 6 || in[0] != 5) { return -EC_GENERAL_FAILURE; }
	if (in[1] != 1) { return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */ }
	if (in[2] != 0) { return -EC_GENERAL_FAILURE; /* malformed packet */ }

	int ret = AF_INET;
	size_t minlen = 4 + 4 + 2, len;
	char host[256], port[8];
	switch (in[3]) {
		case AT_IPV6: /* ipv6 */
			ret = AF_INET6;
			minlen = 4 + 16 + 2;
			/* fall through */
		case AT_IPV4: /* ipv4 */
			if (n < minlen) { return -EC_GENERAL_FAILURE; }
			if (host != inet_ntop(ret, &in[4], host, sizeof(host))) {
				return -EC_GENERAL_FAILURE; /* malformed or too long addr */
			}
			break;
		case AT_DNS: /* dns name */
			len = in[4];
			minlen = 4 + 1 + len + 2;
			if (n < minlen) { return -EC_GENERAL_FAILURE; }
			memcpy(host, &in[4 + 1], len);
			host[len] = 0;
			break;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	snprintf(port, sizeof(port), "%u", (unsigned short)((in[minlen - 2] << 8) | in[minlen - 1]));

	struct addrinfo hints = {
		.ai_flags = AI_ADDRCONFIG,
		.ai_family = SOCKADDR_UNION_AF(&bind_addr),
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,
	};
	struct addrinfo* remote = 0;
	/* there's no suitable errorcode in rfc1928 for dns lookup failure */
	if (getaddrinfo(host, port, &hints, &remote)) {
		perror("resolve");
		return -EC_GENERAL_FAILURE;
	}
	if ((ret = socket(remote->ai_family, remote->ai_socktype, 0)) == -1
		|| (SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC
		&& bind(ret, (struct sockaddr*)&bind_addr, SOCKADDR_UNION_LENGTH(&bind_addr)))
		|| connect(ret, remote->ai_addr, remote->ai_addrlen)) {
		close(ret);
		freeaddrinfo(remote);
		switch(errno) {
			case ETIMEDOUT:
				return -EC_TTL_EXPIRED;
			case EPROTOTYPE:
			case EPROTONOSUPPORT:
			case EAFNOSUPPORT:
				return -EC_ADDRESSTYPE_NOT_SUPPORTED;
			case ECONNREFUSED:
				return -EC_CONN_REFUSED;
			case ENETDOWN:
			case ENETUNREACH:
				return -EC_NET_UNREACHABLE;
			case EHOSTUNREACH:
				return -EC_HOST_UNREACHABLE;
			case EBADF:
			default:
				perror("socket/connect");
				return -EC_GENERAL_FAILURE;
		}
	}
	freeaddrinfo(remote);

	if(CONFIG_LOG) {
		char name[256];
		inet_ntop(SOCKADDR_UNION_AF(&client->addr), SOCKADDR_UNION_ADDRESS(&client->addr), name, sizeof(name));
		dolog("client[%d] %s: connected to %s:%s\n", client->fd, name, host, port);
	}
	return ret;
}

static int is_authed(union sockaddr_union* client, union sockaddr_union* authedip) {
	if (SOCKADDR_UNION_AF(client) == SOCKADDR_UNION_AF(authedip)
		&& !memcmp(client, authedip, SOCKADDR_UNION_LENGTH(client))) {
		return 1;
	}
	return 0;
}

static int is_in_authed_list(union sockaddr_union* addr) {
	size_t i;
	for (i = sblist_getsize(auth_ips) - 1; i + 1 > 0; --i) {
		if (is_authed(addr, sblist_get(auth_ips, i))) { return 1; }
	}
	return 0;
}

static void add_auth_ip(union sockaddr_union* addr) {
	sblist_add(auth_ips, addr);
}

static enum authmethod check_auth_method(struct client* client, unsigned char* in, ssize_t n) {
	// 至少3字节
	if (n < 3 || in[0] != 5) { return AM_INVALID; }
	for (n = MIN(n, in[1] + 2) - 1; n + 1 > 2; --n) {
		switch (in[n]) {
			case AM_NO_AUTH:
				if (!auth_user) { return AM_NO_AUTH; }
				else if (auth_ips) {
					int authed = 0;
					if (!pthread_rwlock_rdlock(&auth_ips_lock)) {
						authed = is_in_authed_list(&client->addr);
						pthread_rwlock_unlock(&auth_ips_lock);
					}
					if (authed) { return AM_NO_AUTH; }
				}
				break;
			case AM_USERNAME:
				if (auth_user) { return AM_USERNAME; }
				break;
			default:
				break;
		}
	}
	return AM_INVALID;
}

static void send_auth_response(int fd, unsigned char *in, enum errorcode code) {
	unsigned char buf[2] = { in[0], code, };
	write(fd, buf, 2);
}

static void send_code(int fd, unsigned char *in, enum errorcode code) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	unsigned char buf[10] = { in[0], code, 0, 1 /*AT_IPV4*/, 0, 0, 0, 0, 0, 0 };
	write(fd, buf, 10);
}

static void copyloop(int fd1, unsigned char *in, int fd2) {
	unsigned char buf[4] = { in[0], 0, 0, in[3], };
	struct pollfd fds[2] = {
		[0] = { .fd = fd1, .events = POLLIN, },
		[1] = { .fd = fd2, .events = POLLIN, },
	};

	for (;;) {
		/* inactive connections are reaped after 15 min to free resources.
		   usually programs send keep-alive packets so this should only happen
		   when a connection is really unused. */
		switch (poll(fds, 2, 15 * 60 * 1000)) {
			case 0:
				send_code(fd1, buf, EC_TTL_EXPIRED);
				return;
			case -1:
				if (errno == EINTR || errno == EAGAIN) { continue; }
				perror("poll");
				return;
			default:
				break;
		}
		int infd, outfd;
		if (fds[0].revents & POLLIN) { infd = fd1; outfd = fd2; }
		else { infd = fd2; outfd = fd1; }
		ssize_t i, n = read(infd, in, THREAD_BUFFER_SIZE);
		if (n <= 0) { return; }
		for (i = 0; i < n;) {
			ssize_t t = write(outfd, &in[i], n - i);
			if (t < 0) { return; }
			i += t;
		}
	}
}

static enum errorcode check_credentials(unsigned char* in, size_t n) {
	// 至少5个字节
	if (n < 5 || in[0] != 1) { return EC_GENERAL_FAILURE; }
	unsigned char ulen, plen;
	if (n < 2 + (ulen = in[1]) + 2
		|| n < 2 + ulen + 1 + (plen = in[ulen + 2])) { return EC_GENERAL_FAILURE; }
	char user[256], pass[256];
	memcpy(user, &in[2], ulen);
	memcpy(pass, &in[2 + ulen + 1], plen);
	user[ulen] = 0;
	pass[plen] = 0;
	if (strcmp(user, auth_user) || strcmp(pass, auth_pass)) { return EC_NOT_ALLOWED; }
	return EC_SUCCESS;
}

static void* clientthread(void* data) {
	struct thread* t = data;
	int ret;
	ssize_t n;
	unsigned char buf[THREAD_BUFFER_SIZE];
	enum socksstate state = SS_1_CONNECTED;
	for (; (n = recv(t->client.fd, buf, THREAD_BUFFER_SIZE, 0)) > 0;) {
		switch (state) {
			case SS_1_CONNECTED:
				ret = check_auth_method(&t->client, buf, n);
				send_auth_response(t->client.fd, buf, ret);
				if (ret == AM_USERNAME) { state = SS_2_NEED_AUTH; }
				else if (ret == AM_NO_AUTH) { state = SS_3_AUTHED; }
				else { goto breakloop; }
				break;
			case SS_2_NEED_AUTH:
				ret = check_credentials(buf, n);
				send_auth_response(t->client.fd, buf, ret);
				if (ret == EC_SUCCESS) {
					state = SS_3_AUTHED;
					if (auth_ips && !pthread_rwlock_wrlock(&auth_ips_lock)) {
						if (!is_in_authed_list(&t->client.addr)) { add_auth_ip(&t->client.addr); }
						pthread_rwlock_unlock(&auth_ips_lock);
					}
				}
				else { goto breakloop; }
				break;
			case SS_3_AUTHED:
				ret = connect_socks_target(&t->client, buf, n);
				if (ret < 0) {
					send_code(t->client.fd, buf, -ret);
				}
				else {
					send_code(t->client.fd, buf, EC_SUCCESS);
					copyloop(t->client.fd, buf, ret);
					close(ret);
				}
				/* fall through */
			default:
				goto breakloop;
		}
	}
breakloop:
	close(t->client.fd);
	t->done = 1;
	return 0;
}

static void collect(sblist *threads) {
	size_t i;
	for (i = sblist_getsize(threads) - 1; i + 1 > 0; --i) {
		struct thread* thread = *((struct thread**)sblist_get(threads, i));
		if (thread->done) {
			sblist_delete(threads, i);
			pthread_join(thread->pt, 0);
			free(thread);
		}
	}
}

static int server_listen(struct addrinfo* addr) {
	int fd = -1, reuse = 1;
	struct addrinfo* p;
	for (p = addr; p; p = p->ai_next) {
		if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) { continue; }
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
		if (bind(fd, p->ai_addr, p->ai_addrlen) || listen(fd, SOMAXCONN)) {
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(addr);
	return fd;
}

/* prevent username and password from showing up in top. */
static void fill_zero(char* s) {
	size_t i;
	for (i = 0; s[i]; ++i) s[i] = 0;
}

static void usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5 Server\n"
		"------------------------\n"
		"usage: microsocks -1 -i listenip -p port -u user -P password -b bindaddr\n"
		"all arguments are optional.\n"
		"by default listenip is 0.0.0.0 and port 1080.\n\n"
		"option -b specifies which ip outgoing connections are bound to\n"
		"option -1 activates auth_once mode: once a specific ip address\n"
		"authed successfully with user/pass, it is added to a whitelist\n"
		"and may use the proxy without auth.\n"
		"this is handy for programs like firefox that don't support\n"
		"user/pass auth. for it to work you'd basically make one connection\n"
		"with another program that supports it, and then you can use firefox too.\n"
	);
}

static struct addrinfo* param_resolve(int argc, char* argv[]) {
	// 解析TCP地址，AI_PASSIVE置位，0返回通配地址
	static const struct addrinfo hints = {
		.ai_flags = AI_ADDRCONFIG | AI_PASSIVE,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,
	};
	struct addrinfo* addr = 0;
	const char* listen_ip = 0;
	const char* listen_port = "1080";
	// 解析参数
	int ch;
	for (; (ch = getopt(argc, argv, ":b:i:p:u:P:1")) != -1; ) {
		switch (ch) {
			case 'i':
				listen_ip = optarg;
				break;
			case 'p':
				listen_port = optarg;
				break;
			case 'b':
				if (getaddrinfo(optarg, 0, &hints, &addr)) {
					perror("bindaddr_resolve");
					return 0;
				}
				memcpy(&bind_addr, addr->ai_addr, addr->ai_addrlen);
				freeaddrinfo(addr);
				break;
			case 'u':
				auth_user = strdup(optarg);
				fill_zero(optarg);
				break;
			case 'P':
				auth_pass = strdup(optarg);
				fill_zero(optarg);
				break;
			case '1':
				auth_ips = sblist_new(sizeof(union sockaddr_union), 8);
				break;
			case ':':
				dprintf(2, "error: option -%c requires an operand\n", optopt);
				/* fall through */
			case '?':
				usage();
				return 0;
		}
	}
	if ((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
		dprintf(2, "error: user and pass must be used together\n");
		return 0;
	}
	if (auth_ips && !auth_user) {
		dprintf(2, "error: auth-once option must be used together with user/pass\n");
		return 0;
	}

	// 解析TCP地址
	if (getaddrinfo(listen_ip, listen_port, &hints, &addr)) {
		perror("listenaddr_resolve");
		return 0;
	}
	return addr;
}

static jmp_buf jmpbuf;
static void quit(int signum) {
	longjmp(jmpbuf, -1);
}
int main(int argc, char* argv[]) {
	// 创建ArrayList，查看元素
	sblist* threads = sblist_new(sizeof(struct thread*), 8);
	if (!threads) {
		perror("sblist_new");
		return -1;
	}

	// 对端close后，避免调用write进程退出
	signal(SIGPIPE, SIG_IGN);
	int fd = server_listen(param_resolve(argc, argv));
	if (fd == -1) {
		free(threads);
		perror("server_setup");
		return -2;
	}
	// 注册退出函数
	if (setjmp(jmpbuf) || signal(SIGINT, quit) == SIG_ERR) {
		perror("setjmp/signal");
		goto exit;
	}
	for (;;) {
		struct thread* thread = malloc(sizeof(struct thread));
		socklen_t addrlen = sizeof(thread->client.addr);
		if (!thread || (thread->client.fd = accept(fd, (struct sockaddr*)&thread->client.addr, &addrlen)) == -1) {
			dolog("rejecting connection due to OOM\n");
			goto oom;
		}

		thread->done = 0;
		pthread_attr_t attr;
		if (pthread_attr_init(&attr)) {
			close(thread->client.fd);
			goto oom;
		}
		if (pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE)
			|| pthread_create(&thread->pt, &attr, clientthread, thread)) {
			dolog("pthread_attr/create failed. OOM?\n");
			pthread_attr_destroy(&attr);
			close(thread->client.fd);
		oom:
			free(thread);
			usleep(16); /* prevent 100% CPU usage in OOM situation */
			continue;
		}
		pthread_attr_destroy(&attr);

		collect(threads);
		if (!sblist_add(threads, &thread)) {
			dolog("sblist_add failed. OOM?\n");
			pthread_join(thread->pt, 0);
			free(thread);
		}
	}
exit:
	close(fd);
	free(threads);
	return 0;
}

