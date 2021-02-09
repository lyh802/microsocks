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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <errno.h>
#include <limits.h>
#include "sbholder.h"
#include "sblist.h"

#define MAX_THREADS -1
#define MAX_EVENTS 128
#define THREAD_BUFFER_SIZE 1460

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef PTHREAD_STACK_MIN
#define THREAD_STACK_SIZE MAX(32*1024, PTHREAD_STACK_MIN)
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
	SS_4_ESTABLISHED = -1,
	// 所有其他值都代表SS_CLOSING
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
	AM_INVALID = -1,
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

#define SOCKADDR_UNION_AF(PTR) (PTR)->v4.sin_family

#define SOCKADDR_UNION_LENGTH(PTR) (\
	(SOCKADDR_UNION_AF(PTR) == AF_INET6) ? sizeof((PTR)->v6) : sizeof((PTR)->v4))

#define SOCKADDR_UNION_ADDRESS(PTR) (\
	(SOCKADDR_UNION_AF(PTR) == AF_INET6) ? (struct sockaddr *)&(PTR)->v6.sin6_addr : (struct sockaddr *)&(PTR)->v4.sin_addr)

#define SOCKADDR_UNION_PORT(PTR) (\
	(SOCKADDR_UNION_AF(PTR) == AF_INET6) ? &(PTR)->v6.sin6_port : &(PTR)->v4.sin_port)

struct buffer {
	size_t count;
	size_t capacity;
	uint8_t data[THREAD_BUFFER_SIZE];
};

struct client {
	int fd[2];
	struct buffer *buf[2];
	volatile int state;
	pthread_t pt;
};

static const char *auth_user = 0;
static const char *auth_pass = 0;
static sblist *auth_ips = 0;
static pthread_rwlock_t auth_ips_lock = PTHREAD_RWLOCK_INITIALIZER;
static union sockaddr_union bind_addr = { .v4.sin_family = AF_UNSPEC, };
// listen解析TCP地址，AI_PASSIVE置位，0返回通配地址
static struct addrinfo hints = {
	.ai_flags = AI_ADDRCONFIG | AI_PASSIVE,
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
};

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) dprintf(2, __VA_ARGS__)
#else
static void dolog(const char *fmt, ...) { }
#endif

static int socks5_connect(union sockaddr_union *remote, int ai_socktype) {
	int ret;
	if ((ret = socket(SOCKADDR_UNION_AF(remote), ai_socktype | SOCK_NONBLOCK, 0)) < 0
		|| (SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC
		&& bind(ret, (struct sockaddr *)&bind_addr, SOCKADDR_UNION_LENGTH(&bind_addr)))
		|| (connect(ret, (struct sockaddr *)remote, SOCKADDR_UNION_LENGTH(remote)) && errno != EINPROGRESS)) {
		perror("socket/bind/connect");
		close(ret);
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
				return -EC_GENERAL_FAILURE;
		}
	}
	return ret;
}

static int socks5_proxy(union sockaddr_union *client, uint8_t *buf, size_t n) {
#if CONFIG_LOG
	inet_ntop(SOCKADDR_UNION_AF(client), SOCKADDR_UNION_ADDRESS(client), (char *)&buf[4+1+255+2], INET6_ADDRSTRLEN);
#endif
	// 头部固定4字节
	if (n < 4 || buf[0] != 5 || buf[2] != 0) { return -EC_GENERAL_FAILURE; /* malformed packet */ }
	if (buf[1] != 1) { return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */ }

	int ret = AF_INET;
	size_t i = 4 + 4;	// 端口
	union sockaddr_union *remote = (union sockaddr_union *)&buf[32];
	switch (buf[3]) {
		case AT_IPV6: /* ipv6 */
			ret = AF_INET6;
			i = 4 + 16;
			remote->v6.sin6_flowinfo = 0;
			remote->v6.sin6_scope_id = 0;
			/* fall through */
		case AT_IPV4: /* ipv4 */
			if (i + 2 > n) { return -EC_GENERAL_FAILURE; }	// IPV6最大长度为4+16+2

			memset(remote->v4.sin_zero, 0, sizeof(remote->v4.sin_zero));
			memcpy(SOCKADDR_UNION_ADDRESS(remote), &buf[4], i - 4);
			*SOCKADDR_UNION_PORT(remote) = *(uint16_t *)&buf[i];
			SOCKADDR_UNION_AF(remote) = ret;
		#if CONFIG_LOG
			inet_ntop(SOCKADDR_UNION_AF(remote), SOCKADDR_UNION_ADDRESS(remote), (char *)&buf[64], INET6_ADDRSTRLEN);
			dolog("client %s: connected to %s:%d\n", (char *)&buf[4+1+255+2], (char *)&buf[64], ntohs(*SOCKADDR_UNION_PORT(remote)));
		#endif
			return socks5_connect(remote, SOCK_STREAM);
		case AT_DNS: /* dns name */
			i = 4 + 1 + buf[4];
			if (i + 2 > n) { return -EC_GENERAL_FAILURE; }	// DNS最大长度为4+1+255+2

			uint16_t port = *(uint16_t *)&buf[i];
			buf[i] = 0;	// 设置host结束符
		#if CONFIG_LOG
			dolog("client %s: connected to %s:%d\n", (char *)&buf[4+1+255+2], (char *)&buf[4+1], ntohs(port));
		#endif
			/* there's no suitable errorcode in rfc1928 for dns lookup failure */
			struct addrinfo *p, *addr;
			ret = getaddrinfo((char *)&buf[4+1], 0, &hints, &addr);
			*(uint16_t *)&buf[i] = port;	// 恢复原始数据
			if (ret) {
				dolog("proxy_resolve: %s\n", gai_strerror(ret));
				return -EC_GENERAL_FAILURE;
			}
			for (p = addr; p; p = p->ai_next) {
				//dolog("retry: %d, next: %d\n", i, p->ai_next);
				*SOCKADDR_UNION_PORT((union sockaddr_union *)p->ai_addr) = port;
				if ((ret = socks5_connect((union sockaddr_union *)p->ai_addr, p->ai_socktype)) >= 0) {
					break;
				}
			}
			freeaddrinfo(addr);
			return ret;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
}

static int is_authed(union sockaddr_union *client, union sockaddr_union *authed) {
	if (SOCKADDR_UNION_AF(client) != SOCKADDR_UNION_AF(authed)
		|| memcmp(client, authed, SOCKADDR_UNION_LENGTH(authed))) {
		return 0;
	}
	return 1;
}

static int is_in_authed_list(union sockaddr_union *client) {
	size_t i;
	for (i = sblist_getsize(auth_ips); i-- > 0;) {
		if (is_authed(client, sblist_get(auth_ips, i))) { return 1; }
	}
	return 0;
}

static void add_auth_ip(union sockaddr_union *client) {
	sblist_add(auth_ips, client);
}

static enum authmethod check_auth_method(union sockaddr_union *client, uint8_t *buf, size_t n) {
	// 头部固定2字节
	if (n < 2 || buf[0] != 5) { return AM_INVALID; }
	for (n = MIN(n, buf[1] + 2); n-- > 2;) {
		switch (buf[n]) {
			case AM_NO_AUTH:
				if (!auth_user) { return AM_NO_AUTH; }
				else if (auth_ips) {
					int authed = 0;
					if (!pthread_rwlock_rdlock(&auth_ips_lock)) {
						authed = is_in_authed_list(client);
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

static enum errorcode check_credentials(uint8_t *buf, size_t n) {
	// 至少2个字节
	if (n < 2 || buf[0] != 1) { return EC_GENERAL_FAILURE; }
	uint8_t ulen, plen;
	if (n < 2 + (ulen = buf[1]) + 1
		|| n < 2 + ulen + 1 + (plen = buf[2+ulen])) { return EC_GENERAL_FAILURE; }	// 最大长度为2+255+1+255(+1)
	buf[2+ulen] = 0;	// 原始user结束符
	buf[2+ulen+1+plen] = 0;	// 原始pass结束符
	if (strcmp((char *)&buf[2], auth_user) || strcmp((char *)&buf[2+ulen+1], auth_pass)) { return EC_NOT_ALLOWED; }
	return EC_SUCCESS;
}

static void send_auth_response(int fd, uint8_t *buf, enum errorcode code) {
	buf[1] = code;
	send(fd, buf, 2, MSG_WAITALL);
}

static void send_code(int fd, uint8_t *buf, enum errorcode code) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	buf[1] = code; buf[3] = AT_IPV4; /*AT_IPV4*/
	send(fd, buf, 4 + 4 + 2, MSG_WAITALL);
}

static void *socks5_handle(void *data) {
	struct client *client = data;
	struct epoll_event ev = {
		.events = EPOLLET | EPOLLOUT | EPOLLIN,
		.data.ptr = (unsigned long)client | 1UL,
	};	// 置1后在main中变更状态
	union sockaddr_union addr;
	int ret = sizeof(addr), fd = client->fd[0], epoll_fd = client->fd[1];
	if (getpeername(fd, (struct sockaddr *)&addr, (socklen_t *)&ret)) { goto breakloop; }

	uint8_t buf[2+255+1+255+1];
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
				} else { goto breakloop; }
				break;
			case SS_3_AUTHED:
				ret = socks5_proxy(&addr, buf, ret);
				if (ret < 0) {
					send_code(fd, buf, -ret);
				} else {
					send_code(fd, buf, EC_SUCCESS);
					client->fd[1] = ret;
					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ret, &ev)) {
						perror("epoll_add1");
						// 必须main中清理资源
					} else { return 0; }
					close(ret);
				}
				/* fall through */
			default:
				goto breakloop;
		}
	}
breakloop:
	//shutdown(fd, SHUT_RDWR);
	client->fd[1] = -1;
	epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
	return (void *)-1;
}

static int server_listen(struct addrinfo *addr) {
	int ret = -1, reuse = 1;
	struct addrinfo *p;
	for (p = addr; p; p = p->ai_next) {
		// 非阻塞
		if ((ret = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol)) < 0
			|| setsockopt(ret, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))
			|| bind(ret, p->ai_addr, p->ai_addrlen) || listen(ret, SOMAXCONN)) {
			close(ret);
			ret = -1;
		} else { break; }
	}
	freeaddrinfo(addr);
	return ret;
}

/* prevent username and password from showing up in top. */
static void fill_zero(char *s) {
	size_t i;
	for (i = 0; s[i]; ++i) s[i] = 0;
}

static void usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5 Server\n"
		"------------------------\n"
		"usage: microsocks -b bindaddr -i listenip -p port -u user -P password -1\n"
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

static struct addrinfo *param_resolve(int argc, char *argv[]) {
	struct addrinfo *addr;
	const char *listen_ip = 0;
	const char *listen_port = "1080";
	// 解析参数
	int ret;
	for (; (ret = getopt(argc, argv, ":b:i:p:u:P:1")) >= 0; ) {
		switch (ret) {
			case 'b':
				if ((ret = getaddrinfo(optarg, 0, &hints, &addr))) {
					dolog("bind_resolve: %s\n", gai_strerror(ret));
					return 0;
				}
				memcpy(&bind_addr, addr->ai_addr, addr->ai_addrlen);
				freeaddrinfo(addr);
				break;
			case 'i':
				listen_ip = optarg;
				break;
			case 'p':
				listen_port = optarg;
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
			default:
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
	if ((ret = getaddrinfo(listen_ip, listen_port, &hints, &addr))) {
		dolog("listen_resolve: %s\n", gai_strerror(ret));
		return 0;
	}
	return addr;
}

static int client_handle(struct client *client, uint8_t instance, sbHolder *buffers) {
	size_t i;
	ssize_t n, t;
	struct buffer *buffer;
	if ((buffer = client->buf[instance])) {
		// 仍有数据待发送
		i = buffer->count;
		n = buffer->capacity;
		for (; i < n; i += t) {
			if ((t = send(client->fd[!instance], &buffer->data[i], n - i, MSG_DONTWAIT)) > 0) {}
			else if (t < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				buffer->count = i;
				return 0;
			} else { return -1; }
		}
		if ((client->buf[instance] = sbholder_free(buffers, client->buf[instance]))) {
			dolog("client_handle/free failed.\n");
		}
	}
	uint8_t buf[THREAD_BUFFER_SIZE];
	for (; (n = recv(client->fd[instance], buf, sizeof(buf), MSG_DONTWAIT)) > 0;) {
		for (i = 0; i < n; i += t) {
			if ((t = send(client->fd[!instance], &buf[i], n - i, MSG_DONTWAIT)) > 0) {}
			else if (t < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				// 数据未发完
				if (!(buffer = sbholder_alloc(buffers))) {
					dolog("client_handle/alloc failed. OOM?\n");
					return -1;
				}
				client->buf[instance] = buffer;
				buffer->count = 0;
				buffer->capacity = n - i;
				memcpy(buffer->data, &buf[i], n - i);
				return 0;
			} else { return -1; }
		}
	}
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { return 0; }
	else { return -1; }	// 需要关闭
}

static int server_handle(struct client *server, sbHolder *clients) {
	int fd, epoll_fd = server->fd[1];
	struct client *client;
	for (; server->pt < MAX_THREADS
		&& (fd = accept4(server->fd[0], 0, 0, 0)) >= 0
		&& (client = sbholder_alloc(clients)); ++server->pt) {
		client->fd[0] = fd;
		client->fd[1] = epoll_fd;
		client->buf[0] = 0;
		client->buf[1] = 0;
		client->state = SS_1_CONNECTED;
		struct epoll_event ev = {
			.events = EPOLLET | EPOLLOUT | EPOLLIN,
			.data.ptr = (unsigned long)client | 0UL,
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev)) {
			perror("epoll_add0");
			goto oom;
		}

		pthread_attr_t attr;
		if (!pthread_attr_init(&attr)) {
			if (pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE)
				|| pthread_create(&client->pt, &attr, socks5_handle, client)) {
				dolog("pthread_attr/create failed. OOM?\n");
				pthread_attr_destroy(&attr);
				goto oom;
			}
			pthread_attr_destroy(&attr);
		} else {
			dolog("pthread_attr_init failed. OOM?\n");
		oom:
			sbholder_free(clients, client);
			break;
		}
	}
	// 可能还有连接，ET模式忽略accept事件
	if (server->pt < MAX_THREADS) {
		if (fd >= 0) {
			dolog("rejecting connection due to OOM?\n");
			close(fd);
			// TODO: 重新设置errno
			errno = ENOMEM;
		} else if (errno == EAGAIN || errno == EWOULDBLOCK
			|| errno == ECONNABORTED || errno == EPROTO) {
			return 0;
		}
		//return -1;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	// 对端shutdown后，避免调用write进程退出
	int ret, epoll_fd;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR
		|| (epoll_fd = epoll_create(MAX_EVENTS)) < 0) {
		perror("signal/epoll_create");
		return -1;
	}

	sbHolder buffers, clients;
	sbholder_init(&buffers, sizeof(struct buffer));
	sbholder_init(&clients, sizeof(struct client));
	struct client *client, *server;
	if (!(server = sbholder_alloc(&clients))) {
		perror("sbholder_alloc");
		close(epoll_fd);
		return -2;
	}

	server->fd[1] = epoll_fd;
	server->state = SS_4_ESTABLISHED;
	server->pt = 0;	// 记录线程数
	struct epoll_event events[MAX_EVENTS], ev = {
		.events = EPOLLET | EPOLLIN,
		.data.ptr = (unsigned long)server | 0UL,
	};
	if ((server->fd[0] = server_listen(param_resolve(argc, argv))) < 0
		|| epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server->fd[0], &ev)) {
		perror("server_listen/epoll_add");
		goto exit;
	}

	// connect时的resolve配置
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_family = SOCKADDR_UNION_AF(&bind_addr);
	for (; (ret = epoll_wait(epoll_fd, events, MAX_EVENTS, -1)) > 0;) {
		size_t i;
		for (i = 0; i < ret; ++i) {
			uint8_t instance = (unsigned long)events[i].data.ptr & 1UL;
			client = (unsigned long)events[i].data.ptr & ~1UL;
			switch (client->state) {
				case SS_1_CONNECTED:
				case SS_2_NEED_AUTH:
				case SS_3_AUTHED:
					if (!instance) { break; }
					// instance=1表示进入建立状态
					client->state = SS_4_ESTABLISHED;
					pthread_join(client->pt, 0);
					// TODO: 从client中获取对应的server，重新触发accept事件
					--server->pt;
					//dolog("Threads: %d\n", server->pt);
					epoll_ctl(server->fd[1], EPOLL_CTL_MOD, server->fd[0], &ev);
					/* fall through */
				case SS_4_ESTABLISHED:
					// 出现错误，由读写回调来处理错误
					if ((events[i].events & (EPOLLHUP | EPOLLERR))) {
						events[i].events |= EPOLLOUT | EPOLLIN;
					}
					if (client->fd[1] == epoll_fd) {
						// 服务端
						if (((events[i].events & EPOLLIN) && server_handle(client, &clients))) {
							// 需要关闭
							client->state = i;
							// epoll_fd不用关闭
							close(client->fd[0]);
						}
					} else {
						// 客户端
						// 按位或运算
						if (((events[i].events & EPOLLIN) && client_handle(client, instance, &buffers))
							| ((events[i].events & EPOLLOUT) && client_handle(client, !instance, &buffers))) {
							client->state = i;
							sbholder_free(&buffers, client->buf[1]);
							sbholder_free(&buffers, client->buf[0]);
							close(client->fd[1]);
							close(client->fd[0]);
						}
					}
					break;
				default:
					// 所有其他值都代表SS_CLOSING
					client->state = i;	// 更新最后引用
					break;
			}
		}
		for (i = 0; i < ret; ++i) {
			client = (unsigned long)events[i].data.ptr & ~1UL;
			// 无符号比较，在最后引用时执行清理
			if (client->state <= i) { sbholder_free(&clients, client); }
		}
	}
	perror("epoll_pwait");
exit:
	close(server->fd[0]);
	close(epoll_fd);
	return 0;
}
