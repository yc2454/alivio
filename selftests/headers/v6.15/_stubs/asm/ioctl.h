/* Stub: <asm/ioctl.h> — ioctl direction-encoding macros.
 *
 * Mirrors include/uapi/asm-generic/ioctl.h. Only `test_lirc_mode2_kern.c`
 * needs this from BPF compile context (for LIRC_MODE2_* macros).
 */
#ifndef _ALIVIO_STUB_ASM_IOCTL_H
#define _ALIVIO_STUB_ASM_IOCTL_H

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8
#define _IOC_SIZEBITS  14
#define _IOC_DIRBITS    2

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT + _IOC_SIZEBITS)

#define _IOC_NONE  0U
#define _IOC_WRITE 1U
#define _IOC_READ  2U

#define _IOC(dir,type,nr,size) \
    (((dir)  << _IOC_DIRSHIFT)  | \
     ((type) << _IOC_TYPESHIFT) | \
     ((nr)   << _IOC_NRSHIFT)   | \
     ((size) << _IOC_SIZESHIFT))

#define _IOC_TYPECHECK(t) (sizeof(t))

#define _IO(type,nr)        _IOC(_IOC_NONE, (type), (nr), 0)
#define _IOR(type,nr,size)  _IOC(_IOC_READ, (type), (nr), _IOC_TYPECHECK(size))
#define _IOW(type,nr,size)  _IOC(_IOC_WRITE,(type), (nr), _IOC_TYPECHECK(size))
#define _IOWR(type,nr,size) _IOC(_IOC_READ|_IOC_WRITE, (type), (nr), _IOC_TYPECHECK(size))

#endif
