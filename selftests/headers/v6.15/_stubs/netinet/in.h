/* Stub: <netinet/in.h> for `clang -target bpf` builds.
 *
 * Re-export the kernel UAPI equivalents (struct in_addr, in6_addr,
 * sockaddr_in, IPPROTO_*, htons/htonl macros via linux/in.h).
 */
#ifndef _ALIVIO_STUB_NETINET_IN_H
#define _ALIVIO_STUB_NETINET_IN_H

/* Pull <sys/socket.h> too — libc's <netinet/in.h> does the same, and
 * selftests sources rely on it for AF_*, SOL_*, struct sockaddr. */
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

#endif
