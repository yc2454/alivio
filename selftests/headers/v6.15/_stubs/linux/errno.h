#ifndef _ALIVIO_STUB_LINUX_ERRNO_H
#define _ALIVIO_STUB_LINUX_ERRNO_H
#define EPERM   1
#define ENOENT  2
#define ESRCH   3
#define EINTR   4
#define EIO     5
#define ENXIO   6
#define E2BIG   7
#define ENOEXEC 8
#define EBADF   9
#define ECHILD 10
#define EAGAIN 11
#define EDEADLK 35
#define EDEADLOCK EDEADLK
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define EBUSY  16
#define EEXIST 17
#define EXDEV  18
#define ENODEV 19
#define ENOTDIR 20
#define EISDIR 21
#define EINVAL 22
#define ENFILE 23
#define EMFILE 24
#define ENOSPC 28
#define ESPIPE 29
#define EROFS  30
#define EMLINK 31
#define EPIPE  32
#define ERANGE 34
#define ENAMETOOLONG 36
#define ENOSYS 38
#define ELOOP  40
#define EOPNOTSUPP 95
#define EAFNOSUPPORT 97
#define ETIMEDOUT 110
#define ENOTSUPP 524

/* Less-common errno values (selftests reference a long tail). */
#define EUNATCH  49   /* Protocol driver not attached */
#define ENOMSG   42   /* No message of desired type */
#define EBADMSG  74   /* Not a data message */
#define ESOCKTNOSUPPORT 94
#define EISCONN 106   /* Transport endpoint is already connected */
#define ENOTCONN 107  /* Transport endpoint is not connected */
#define ECONNREFUSED 111
#define EHOSTUNREACH 113
#endif
