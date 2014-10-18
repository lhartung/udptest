#ifndef TSUTIL_H
#define TSUTIL_H

#define MSECS_PER_SEC 1000
#define USECS_PER_SEC 1000000
#define USECS_PER_MSEC 1000
#define NSECS_PER_SEC 1000000000
#define NSECS_PER_USEC 1000
#define NSECS_PER_MSEC 1000000

/* Store a time as microseconds (on 32-bit builds) or nanoseconds (on 64-bit builds).
 * Application code should avoid reading a tsval_t directly because of that. */
typedef long tsval_t;

#if defined(__LP64__)
#define TSVAL_BASE 1000000000
#else
#define TSVAL_BASE 1000000
#endif

struct timespec;

tsval_t timespec_diff(const struct timespec *a, const struct timespec *b);
void timespec_add(struct timespec *a, tsval_t amount);
void timespec_fill(tsval_t value, struct timespec *dest);
void timespec_sub(const struct timespec *a, const struct timespec *b, struct timespec *dest);

tsval_t apply_time_suffix(long value, char suffix);

static inline long tsval_to_usecs(tsval_t value) {
#if defined(__LP64__)
    return value / NSECS_PER_USEC;
#else
    return value;
#endif
}

#endif /* TSUTIL_H */
