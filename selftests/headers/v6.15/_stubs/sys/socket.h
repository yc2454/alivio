/* Stub: <sys/socket.h> for `clang -target bpf` builds.
 *
 * The bpf selftests share some prog sources with userspace test
 * harnesses, which pull in this header for AF_INET/SOCK_DGRAM and
 * struct sockaddr_in. The BPF compile path doesn't have a libc — but
 * we cover the union of (a) what kernel UAPI provides (struct
 * sockaddr_in via <linux/in.h>) and (b) what only libc provides
 * (AF_*, SOCK_*, struct sockaddr) — the latter as direct defines.
 *
 * Values match POSIX / glibc on Linux.
 */
#ifndef _ALIVIO_STUB_SYS_SOCKET_H
#define _ALIVIO_STUB_SYS_SOCKET_H

#include <linux/socket.h>   /* __kernel_sa_family_t, struct __kernel_sockaddr_storage */
#include <linux/in.h>       /* struct in_addr, sockaddr_in, IPPROTO_* */
#include <linux/in6.h>      /* struct in6_addr, sockaddr_in6 */

/* Address families. */
#define AF_UNSPEC    0
#define AF_UNIX      1
#define AF_LOCAL     1
#define AF_INET      2
#define AF_INET6    10
#define AF_NETLINK  16
#define AF_PACKET   17

#define PF_UNSPEC   AF_UNSPEC
#define PF_UNIX     AF_UNIX
#define PF_INET     AF_INET
#define PF_INET6    AF_INET6
#define PF_NETLINK  AF_NETLINK
#define PF_PACKET   AF_PACKET

/* Socket types. */
#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3
#define SOCK_RDM        4
#define SOCK_SEQPACKET  5
#define SOCK_DCCP       6
#define SOCK_PACKET    10

/* Generic sockaddr (libc, not provided by kernel UAPI). */
struct sockaddr {
    __kernel_sa_family_t sa_family;
    char                 sa_data[14];
};

/* setsockopt() levels. */
#define SOL_SOCKET 1
#define SOL_IP     0
#define SOL_IPV6  41
#define SOL_TCP    6
#define SOL_UDP   17

/* Common SO_* names referenced by selftests. */
#define SO_DEBUG         1
#define SO_REUSEADDR     2
#define SO_REUSEPORT    15
#define SO_TYPE          3
#define SO_ERROR         4
#define SO_BROADCAST     6
#define SO_SNDBUF        7
#define SO_RCVBUF        8
#define SO_KEEPALIVE     9
#define SO_PRIORITY     12
#define SO_BINDTODEVICE 25
#define SO_MARK         36
#define SO_BINDTOIFINDEX 62

#endif
