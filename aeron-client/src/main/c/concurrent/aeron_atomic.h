/*
 * Copyright 2014-2020 Real Logic Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AERON_ATOMIC_H
#define AERON_ATOMIC_H

#include <stdint.h>
#include <stdbool.h>

#include "util/aeron_platform.h"
#include "turf/c/atomic.h"

#define AERON_GET_VOLATILE(dst, src) \
do \
{ \
    dst = src; \
    turf_threadFenceAcquire(); \
} \
while (false)

#define AERON_PUT_ORDERED(dst, src) \
do \
{ \
    turf_threadFenceRelease(); \
    dst = src; \
} \
while (false)

#define AERON_PUT_VOLATILE(dst, src) \
do \
{ \
    turf_threadFenceRelease(); \
    dst = src; \
    turf_threadFenceAcquire(); \
    turf_threadFenceSeqCst(); \
} \
while (false)


inline int64_t aeron_get_and_add_int64(volatile int64_t* current, int64_t value)
{
    return (int64_t)turf_fetchAdd64Relaxed((turf_atomic64_t*)current, (int64_t)value);
}

inline int32_t aeron_get_and_add_int32(volatile int32_t* current, int32_t value)
{
    return (int32_t)turf_fetchAdd32Relaxed((turf_atomic32_t*)current, (int32_t)value);
} 

inline bool aeron_cmpxchg64(volatile int64_t* destination, int64_t expected, int64_t desired)
{
    uint64_t original = turf_compareExchange64Relaxed((turf_atomic64_t*)destination, (uint64_t)expected, (uint64_t)desired);
    return original == (uint64_t)expected;
}

inline bool aeron_cmpxchgu64(volatile uint64_t* destination, uint64_t expected, uint64_t desired)
{
    uint64_t original = turf_compareExchange64Relaxed((turf_atomic64_t*)destination, (uint64_t)expected, (uint64_t)desired);
    return original == (uint64_t)expected;
}

inline bool aeron_cmpxchg32(volatile int32_t* destination, int32_t expected, int32_t desired)
{
    uint32_t original = turf_compareExchange32Relaxed((turf_atomic32_t*)destination, (uint32_t)expected, (uint32_t)desired);
    return original == (uint32_t)expected;
}

/* https://docs.oracle.com/javase/9/docs/api/java/lang/invoke/VarHandle.html */
/* http://openjdk.java.net/jeps/171 */
/* loadFence */
inline void aeron_acquire()
{
    turf_threadFenceAcquire();
}

/* storeFence */
inline void aeron_release()
{
    turf_threadFenceRelease();
}

/*
//-------------------------------------
//  Alignment
//-------------------------------------
// Note: May not work on local variables.
// http://gcc.gnu.org/bugzilla/show_bug.cgi?id=24691
*/

/*
Refer to 
https://github.com/mozilla/gecko-dev/blob/41d1d7909496a3f672eb9aeed1efec042c9568b0/js/src/jit/AtomicOperations.h
for full implementation
*/

#define AERON_DECL_ALIGNED(declaration, amt) TURF_DECL_ALIGNED(declaration, amt)

#endif //AERON_ATOMIC_H
