#ifndef _ALIVIO_STUB_TIME_H
#define _ALIVIO_STUB_TIME_H
typedef long time_t;

/* clock_gettime(2) IDs — the BPF selftests reference these as the
 * second arg to bpf_timer_init() to pick the underlying kernel clock.
 * Values match the Linux UAPI (uapi/linux/time.h). */
#define CLOCK_REALTIME       0
#define CLOCK_MONOTONIC      1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW  4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME       7
#define CLOCK_REALTIME_ALARM 8
#define CLOCK_BOOTTIME_ALARM 9
#define CLOCK_TAI            11
#endif
