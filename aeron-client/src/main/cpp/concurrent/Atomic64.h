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
#ifndef AERON_CONCURRENT_ATOMIC64_H
#define AERON_CONCURRENT_ATOMIC64_H

#include <atomic>

#include "util/Platform.h"
#include "concurrent/aeron_atomic.h"
#include "concurrent/aeron_thread.h"

namespace aeron { namespace concurrent { namespace atomic {

/**
* A compiler directive not reorder instructions.
*/
inline void thread_fence()
{
    turf_threadFenceAcquire();
    turf_threadFenceRelease();
}

/**
* Fence operation that uses locked addl as mfence is sometimes expensive
*/
inline void fence()
{
    turf_threadFenceSeqCst();
}

inline void acquire()
{
    turf_threadFenceAcquire();
}

inline void release()
{
    turf_threadFenceRelease();
}

/**
* A more jitter friendly alternate to thread:yield in spin waits.
*/
inline void cpu_pause()
{
    turf_yieldHWThread();
}

/**
* Returns a 32 bit integer with volatile semantics.
* On x64 MOV is a SC Atomic a operation.
*/
inline std::int32_t getInt32Volatile(volatile std::int32_t* source)
{
    std::int32_t sequence = *reinterpret_cast<volatile std::int32_t *>(source);
    acquire();
    return sequence;
}

/**
* Put a 32 bit int with ordered semantics
*/
inline void putInt32Ordered(volatile std::int32_t* source, std::int32_t value)
{
    release();
    *reinterpret_cast<volatile std::int32_t *>(source) = value;
}

/**
* Put a 32 bit int with atomic semantics.
**/
inline void putInt32Atomic(volatile std::int32_t*  address, std::int32_t value)
{
    turf_exchange32Relaxed((turf_atomic32_t*)address, value);
}

/**
* Returns a 64 bit integer with volatile semantics.
* On x64 MOV is a SC Atomic a operation.
*/
inline std::int64_t getInt64Volatile(volatile std::int64_t* source)
{
    std::int64_t sequence = *reinterpret_cast<volatile std::int64_t *>(source);
    acquire();
    return sequence;
}

/**
* Put a 64 bit int with ordered semantics.
*/
inline void  putInt64Ordered(volatile std::int64_t*  address, std::int64_t value)
{
    release();
    *reinterpret_cast<volatile std::int64_t *>(address) = value;
}

/**
* Put a 64 bit int with atomic semantics.
**/
inline void putInt64Atomic(volatile std::int64_t*  address, std::int64_t value)
{
    turf_exchange64Relaxed((turf_atomic64_t*)address, value);
}

inline std::int64_t getAndAddInt64(volatile std::int64_t* address, std::int64_t value)
{
    return turf_fetchAdd64Relaxed((turf_atomic64_t*)address, value);
}

inline std::int32_t getAndAddInt32(volatile std::int32_t* address, std::int32_t value)
{
    return turf_fetchAdd32Relaxed((turf_atomic32_t *)address, value);
}

inline std::int32_t cmpxchg(volatile std::int32_t* destination, std::int32_t expected, std::int32_t desired)
{
    return turf_compareExchange32Relaxed((turf_atomic32_t*)destination, expected, desired);
}

inline std::int64_t cmpxchg(volatile std::int64_t* destination,  std::int64_t expected, std::int64_t desired)
{
    return turf_compareExchange64Relaxed((turf_atomic64_t*)destination, expected, desired);
}

}}}

/**
 * Set of Operations to support atomic operations in C++ that are
 * consistent with the same semantics in the JVM.
 */

#endif
