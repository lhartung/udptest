#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

#include "tsutil.h"

#if defined(__LP64__)
const long TSVAL_MAX_SEC    = LONG_MAX / NSECS_PER_SEC;
const long TSVAL_MAX_MSEC   = LONG_MAX / NSECS_PER_MSEC;
const long TSVAL_MAX_USEC   = LONG_MAX / NSECS_PER_USEC;
const long TSVAL_MAX_NSEC   = LONG_MAX;
#else
const long TSVAL_MAX_SEC    = LONG_MAX / USECS_PER_SEC;
const long TSVAL_MAX_MSEC   = LONG_MAX / USECS_PER_MSEC;
const long TSVAL_MAX_USEC   = LONG_MAX;
const long TSVAL_MAX_NSEC   = LONG_MAX;
#endif

tsval_t timespec_diff(const struct timespec *a, const struct timespec *b)
{
#if defined(__LP64__)
    return (a->tv_sec - b->tv_sec) * NSECS_PER_SEC +
           (a->tv_nsec - b->tv_nsec);
#else
    return (a->tv_sec - b->tv_sec) * USECS_PER_SEC +
           (a->tv_nsec - b->tv_nsec) / NSECS_PER_USEC;
#endif
}

void timespec_add(struct timespec *a, tsval_t amount)
{
    assert(amount >= 0);
#if defined(__LP64__)
    a->tv_sec += amount / NSECS_PER_SEC;
    a->tv_nsec += amount % NSECS_PER_SEC;
#else
    a->tv_sec += amount / USECS_PER_SEC;
    a->tv_nsec += NSECS_PER_USEC * (amount % USECS_PER_SEC);
#endif
    assert(a->tv_nsec >= 0);
    assert(a->tv_nsec < NSECS_PER_SEC);
}

void timespec_fill(tsval_t value, struct timespec *dest)
{
    assert(value >= 0);
#if defined(__LP64__)
    dest->tv_sec = value / NSECS_PER_SEC;
    dest->tv_nsec = value % NSECS_PER_SEC;
#else
    dest->tv_sec = value / USECS_PER_SEC;
    dest->tv_nsec = NSECS_PER_USEC * (value % USECS_PER_SEC);
#endif
    assert(dest->tv_nsec >= 0);
    assert(dest->tv_nsec < NSECS_PER_SEC);
}

/*
 * Test if timespec a is after timespec b (a > b).
 */
int timespec_after(const struct timespec *a, const struct timespec *b)
{
    long sec_diff = (long)a->tv_sec - (long)b->tv_sec;
    if(sec_diff > 0) {
        return 1;
    } else if(sec_diff == 0) {
        long nsec_diff = (long)a->tv_nsec - (long)b->tv_nsec;
        return (nsec_diff > 0);
    } else {
        return 0;
    }
}

void timespec_sub(const struct timespec *a, const struct timespec *b, struct timespec *dest)
{
    dest->tv_sec = a->tv_sec - b->tv_sec;
    dest->tv_nsec = a->tv_nsec - b->tv_nsec;
    if(dest->tv_nsec < 0) {
        dest->tv_sec--;
        dest->tv_nsec += NSECS_PER_SEC;
    }
    assert(dest->tv_nsec >= 0);
}

static void overflow_error_message(long value, char suffix)
{
    long max;

    switch(suffix) {
        case 's':
            max = TSVAL_MAX_SEC;
            break;
        case 'm':
            max = TSVAL_MAX_MSEC;
            break;
        case 'u':
            max = TSVAL_MAX_USEC;
            break;
        case 'n':
            max = TSVAL_MAX_NSEC;
            break;
        default:
            max = 0;
    }

    fprintf(stderr, "Specified time (%ld%c) is too large, maximum allowed is %ld%c\n",
            value, suffix, max, suffix);
}

tsval_t apply_time_suffix(long value, char suffix)
{
    tsval_t result = value;

    switch(suffix) {
        case 's':
            if(result > LONG_MAX / 1000) {
                overflow_error_message(value, suffix);
                return -1;
            }
            result *= 1000;
        case 'm':
            if(result > LONG_MAX / 1000) {
                overflow_error_message(value, suffix);
                return -1;
            }
            result *= 1000;
        case 'u':
#if defined(__LP64__) 
            if(result > LONG_MAX / 1000) {
                overflow_error_message(value, suffix);
                return -1;
            }
            result *= 1000;
        case 'n':
#endif      
            break;
        default:
            fprintf(stderr, "Invalid time specification: %ld%c\n", value, suffix);
            return -1;
    }
    
    return result;
}

