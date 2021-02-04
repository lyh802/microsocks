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
#include <netdb.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "sblist.h"

#define MAX_EVENTS 128
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
	SS_1_CONNECTED = -4,
	SS_2_NEED_AUTH = -3, /* skipped if NO_AUTH method supported */
	SS_3_AUTHED = -2,
	SS_CLEANUP = -1,
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

struct buffer {
	size_t count;
	size_t capacity;
	uint8_t data[THREAD_BUFFER_SIZE];
};

struct client {
	volatile int state;
	int fd[2];
	struct buffer* ptr[2];
	pthread_t pt;
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

static int connect_socks_target(union sockaddr_union* client, uint8_t* buf, size_t n) {
	// 头部固定4字节
	if (n < 4 || buf[0] != 5 || buf[2] != 0) { return -EC_GENERAL_FAILURE; /* malformed packet */ }
	if (buf[1] != 1) { return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */ }

	int ret = AF_INET;
	size_t i = 4 + 4;	// 端口
	char port[6];
	switch (buf[3]) {
		case AT_IPV6: /* ipv6 */
			ret = AF_INET6;
			i = 4 + 16;
			/* fall through */
		case AT_IPV4: /* ipv4 */
			if (i + 2 > n) { return -EC_GENERAL_FAILURE; }
			snprintf(port, sizeof(port), "%u", ntohs(*(uint16_t*)&buf[i]));
			if (!inet_ntop(ret, &buf[4], (char*)&buf[i + 2], INET6_ADDRSTRLEN)) {	// IPV6最大长度为4+16+2+45(+1)
				return -EC_GENERAL_FAILURE; /* malformed or too long addr */
			}
			i = i + 2;	// host
			break;
		case AT_DNS: /* dns name */
			i = 4 + 1 + buf[4];
			if (i + 2 > n) { return -EC_GENERAL_FAILURE; }	// DNS最大长度为4+1+255+2
			snprintf(port, sizeof(port), "%u", ntohs(*(uint16_t*)&buf[i]));
			buf[i] = 0;	// 原始host结束符
			i = 4 + 1;	// host
			break;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}

	struct addrinfo hints = {
		.ai_flags = AI_ADDRCONFIG,
		.ai_family = SOCKADDR_UNION_AF(&bind_addr),
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,
	};
	struct addrinfo* addr;
	/* there's no suitable errorcode in rfc1928 for dns lookup failure */
	if (getaddrinfo((char*)&buf[i], port, &hints, &addr)) {
		perror("resolve");
		return -EC_GENERAL_FAILURE;
	}
	if ((ret = socket(addr->ai_family, addr->ai_socktype, 0)) < 0
		|| (SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC
		&& bind(ret, (struct sockaddr*)&bind_addr, SOCKADDR_UNION_LENGTH(&bind_addr)))
		|| connect(ret, addr->ai_addr, addr->ai_addrlen)) {
		close(ret);
		freeaddrinfo(addr);
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
	freeaddrinfo(addr);

	if(CONFIG_LOG) {
		char name[256];
		inet_ntop(SOCKADDR_UNION_AF(client), SOCKADDR_UNION_ADDRESS(client), name, sizeof(name));
		dolog("client %s: connected to %s:%s\n", name, (char*)&buf[i], port);
	}
	return ret;
}

static int is_authed(union sockaddr_union* addr, union sockaddr_union* authed) {
	if (SOCKADDR_UNION_AF(addr) != SOCKADDR_UNION_AF(authed)
		|| memcmp(addr, authed, SOCKADDR_UNION_LENGTH(authed))) {
		return 0;
	}
	return 1;
}

static int is_in_authed_list(union sockaddr_union* addr) {
	size_t i;
	for (i = sblist_getsize(auth_ips); i-- > 0;) {
		if (is_authed(addr, sblist_get(auth_ips, i))) { return 1; }
	}
	return 0;
}

static void add_auth_ip(union sockaddr_union* addr) {
	sblist_add(auth_ips, addr);
}

static enum authmethod check_auth_method(union sockaddr_union* addr, uint8_t* buf, size_t n) {
	// 头部固定2字节
	if (n < 2 || buf[0] != 5) { return AM_INVALID; }
	for (n = MIN(n, buf[1] + 2); n-- > 2;) {
		switch (buf[n]) {
			case AM_NO_AUTH:
				if (!auth_user) { return AM_NO_AUTH; }
				else if (auth_ips) {
					int authed = 0;
					if (!pthread_rwlock_rdlock(&auth_ips_lock)) {
						authed = is_in_authed_list(addr);
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

static enum errorcode check_credentials(uint8_t* buf, size_t n) {
	// 至少3个字节
	if (n < 3 || buf[0] != 1) { return EC_GENERAL_FAILURE; }
	uint8_t ulen, plen;
	if (n < 2 + (ulen = buf[1]) + 1
		|| n < 2 + ulen + 1 + (plen = buf[2 + ulen])) { return EC_GENERAL_FAILURE; }	// 最大长度为2+255+1+255(+1)
	buf[2 + ulen] = 0;	// 原始user结束符
	buf[2 + ulen + 1 + plen] = 0;	// 原始pass结束符
	if (strcmp((char*)&buf[2], auth_user) || strcmp((char*)&buf[2 + ulen + 1], auth_pass)) { return EC_NOT_ALLOWED; }
	return EC_SUCCESS;
}

static void send_auth_response(int fd, uint8_t* buf, enum errorcode code) {
	buf[1] = code;
	send(fd, buf, 2, 0);
}

static void send_code(int fd, uint8_t* buf, enum errorcode code) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	buf[1] = code; buf[3] = AT_IPV4; /*AT_IPV4*/
	send(fd, buf, 4 + 4 + 2, 0);
}

static void* clientthread(void* data) {
	struct client* client = data;
	union sockaddr_union addr;
	int ret = sizeof(addr), fd = client->fd[0];
	if (getpeername(fd, (struct sockaddr*)&addr, (socklen_t*)&ret)) { goto breakloop; }

	uint8_t buf[4+1+255+2];
	for (; (ret = recv(fd, buf, sizeof(buf), 0)) > 0;) {
		switch (client->state) {
			case SS_1_CONNECTED:
				ret = check_auth_method(&addr, buf, ret);
				send_auth_response(fd, buf, ret);
				if (ret == AM_USERNAME) { client->state = SS_2_NEED_AUTH; }
				else if (ret == AM_NO_AUTH) { client->state = SS_3_AUTHED; }
				else { goto breakloop; }
				break;
			case SS_2_NEED_AUTH:
				ret = check_credentials(buf, ret);
				send_auth_response(fd, buf, ret);
				if (ret == EC_SUCCESS) {
					client->state = SS_3_AUTHED;
					if (auth_ips && !pthread_rwlock_wrlock(&auth_ips_lock)) {
						if (!is_in_authed_list(&addr)) { add_auth_ip(&addr); }
						pthread_rwlock_unlock(&auth_ips_lock);
					}
				}
				else { goto breakloop; }
				break;
			case SS_3_AUTHED:
				ret = connect_socks_target(&addr, buf, ret);
				if (ret < 0) {
					perror("connect_socks_target");
					send_code(fd, buf, -ret);
				}
				else {
					send_code(fd, buf, EC_SUCCESS);

					int epoll_fd = client->fd[1];
					client->fd[1] = ret;
					client->ptr[0] = 0;
					client->ptr[1] = 0;
					struct epoll_event ev = {
						.events = EPOLLIN | EPOLLOUT | EPOLLET,
						.data.ptr = (unsigned long)client | 0,
					};
					if (!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev)) {
						ev.data.ptr = (unsigned long)client | 1;
						if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ret, &ev)) {
							perror("epoll_ctl: add1");
						}
						return 0;
                    }
					perror("epoll_ctl: add0");
					close(ret);
				}
				/* fall through */
			default:
				goto breakloop;
		}
	}
breakloop:
	close(fd);
	client->state = SS_CLEANUP;
	return -1;
}

static void copyloop(struct client* client, uint8_t idx, size_t j) {
	uint8_t buf[THREAD_BUFFER_SIZE];
	size_t i;
	ssize_t n, t;
	if (client->ptr[idx]) {
		// 仍有数据待发送
		i = client->ptr[idx]->count;
		n = client->ptr[idx]->capacity;
		for (; i < n && (t = send(client->fd[!idx], &buf[i], n - i, MSG_DONTWAIT)) > 0; i += t) {}
		if (i < n) {
			client->ptr[idx]->count = i;
		} else {
			free(client->ptr[idx]);
			client->ptr[idx] = 0;
		}
	}
	if (!client->ptr[idx]) {
		for (; (n = recv(client->fd[idx], buf, sizeof(buf), MSG_DONTWAIT)) > 0;) {
			for (i = 0; i < n && (t = send(client->fd[!idx], &buf[i], n - i, MSG_DONTWAIT)) > 0; i += t) {}
			if (i < n) { break; }
		}
	}
	if (n > 0) {
		// 数据未发完
		if (client->ptr[idx] = malloc(sizeof(struct buffer))) {
			client->ptr[idx]->count = 0;
			client->ptr[idx]->capacity = n - i;
			memcpy(client->ptr[idx]->data, &buf[i], n - i);
		}
	}
	else if (n == 0 || errno != EAGAIN) {
		// 需要关闭
		client->state = j;
	}
}

static void* copythread(void* data) {
	int ret;
	struct epoll_event events[MAX_EVENTS];
	for (; (ret = epoll_wait(data, events, MAX_EVENTS, -1)) > 0;) {
		size_t i;
		for (i = 0; i < ret; ++i) {
			size_t idx = (unsigned long)events[i].data.ptr & 1;
			struct client* client = (unsigned long)events[i].data.ptr & ~1;
			if (client->state != SS_3_AUTHED) { continue; }
			if (events[i].events & EPOLLIN) { copyloop(client, idx, i); }
			if (events[i].events & EPOLLOUT) { copyloop(client, !idx, i); }
		}
		for (i = 0; i < ret; ++i) {
			struct client* client = (unsigned long)events[i].data.ptr & ~1;
			if (client->state == i) {	// 仅关闭一次
				close(client->fd[0]);
				close(client->fd[1]);
				client->state = SS_CLEANUP;
			}
		}
    }
    perror("epoll_pwait");
	return -1;
}

static void collect(sblist* threads) {
	size_t i;
	for (i = sblist_getsize(threads); i-- > 0;) {
		struct client* client = *((struct client**)sblist_get(threads, i));
		if (client->state == SS_CLEANUP) {
			sblist_delete(threads, i);
			pthread_join(client->pt, 0);
			free(client);
		}
	}
}

static int server_listen(struct addrinfo* addr) {
	int fd = -1, reuse = 1;
	struct addrinfo* p;
	for (p = addr; p; p = p->ai_next) {
		if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0
			|| setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))
			|| bind(fd, p->ai_addr, p->ai_addrlen) || listen(fd, SOMAXCONN)) {
			close(fd);
			fd = -1;
		} else { break; }
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
		"usage: microsocks  -b bindaddr -i listenip -p port -u user -P password -1\n"
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
	struct addrinfo* addr;
	const char* listen_ip = 0;
	const char* listen_port = "1080";
	// 解析参数
	int ch;
	for (; (ch = getopt(argc, argv, ":b:i:p:u:P:1")) >= 0; ) {
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
	if (!auth_user ^ !auth_pass) {
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
	int listen_fd, epoll_fd;
	if ((listen_fd = server_listen(param_resolve(argc, argv))) < 0
		|| (epoll_fd = epoll_create(MAX_EVENTS)) < 0) {
		perror("server_listen/epoll_create");
		close(listen_fd);
		return -1;
	}

	pthread_t pthread;
	if (pthread_create(&pthread, 0, copythread, epoll_fd)) {
		perror("pthread_create");
		close(epoll_fd);
		close(listen_fd);
		return -2;
	}

	// 创建ArrayList，查看元素
	sblist* threads;
	if (!(threads = sblist_new(sizeof(struct client*), 8))) {
		perror("sblist_new");
		goto exit;
	}

	// 注册退出函数
	if (setjmp(jmpbuf) || signal(SIGINT, quit) == SIG_ERR
		|| signal(SIGPIPE, SIG_IGN) == SIG_ERR) {// 对端close后，避免调用write进程退出
		perror("setjmp/signal");
		goto exit;
	}
	for (;;) {
		struct client* client;
		for (; (client = malloc(sizeof(struct client)))
			&& (client->fd[0] = accept(listen_fd, 0, 0)) >= 0;) {
			client->fd[1] = epoll_fd;
			client->state = SS_1_CONNECTED;
			collect(threads);
			pthread_attr_t attr;
			if (!pthread_attr_init(&attr)) {
				if (pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE)
					|| pthread_create(&client->pt, &attr, clientthread, client)) {
					dolog("pthread_attr/create failed. OOM?\n");
					pthread_attr_destroy(&attr);
					close(client->fd[0]);
					break;
				}
				pthread_attr_destroy(&attr);
				if (!sblist_add(threads, &client)) {
					dolog("sblist_add failed. OOM?\n");
					pthread_join(client->pt, 0);	// 等待该线程结束
				}
			}
		}
		dolog("rejecting connection due to OOM\n");
		free(client);
		usleep(16); /* prevent 100% CPU usage in OOM situation */
	}
exit:
	free(threads);
	close(epoll_fd);
	close(listen_fd);
	return 0;
}
