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

#ifndef AERON_TESTUTILS_H
#define AERON_TESTUTILS_H

extern "C"
{
#include <util/aeron_fileutil.h>
#include <util/aeron_error.h>
#include <aeron_common.h>
}

#include "util/Exceptions.h"
#include "ChannelUriStringBuilder.h"

namespace aeron { namespace test {

std::string makeTempFileName(size_t size)
{
    char filename[AERON_MAX_PATH];
    if (aeron_log_buffer_filename_create_direct(filename, sizeof(filename) - 1, AERON_LOG_BUFFER_TYPE_IPC, rand(), size) < 0)
    {
        throw util::IOException(std::string("Failed to makeTempFileName file: ") + filename + " " + aeron_errmsg(), SOURCEINFO);
    }
    return std::string(filename);
}

inline void throwIllegalArgumentException()
{
    throw util::IllegalArgumentException("Intentional IllegalArgumentException", SOURCEINFO);
}

ChannelUriStringBuilder &setParameters(const char *media, const char *endpoint, ChannelUriStringBuilder &builder)
{
    builder.media(media);
    if (endpoint)
    {
        builder.endpoint(endpoint);
    }

    return builder;
}

}}

#define AERON_TEST_TIMEOUT (5000)

#define WAIT_FOR_NON_NULL(val, op)               \
auto val = op;                                   \
do                                               \
{                                                \
    std::int64_t t0 = aeron_epoch_clock();       \
    while (!val)                                 \
    {                                            \
       ASSERT_LT(aeron_epoch_clock() - t0, AERON_TEST_TIMEOUT) << "Failed waiting for: "  << #op; \
       std::this_thread::yield();                \
       val = op;                                 \
    }                                            \
}                                                \
while (0)                                        \

#define WAIT_FOR(op)                             \
do                                               \
{                                                \
    std::int64_t t0 = aeron_epoch_clock();       \
    while (!(op))                                \
    {                                            \
       ASSERT_LT(aeron_epoch_clock() - t0, AERON_TEST_TIMEOUT) << "Failed waiting for: " << #op; \
       std::this_thread::yield();                \
    }                                            \
}                                                \
while (0)                                        \

#define POLL_FOR_NON_NULL(val, op, invoker) \
auto val = op;                              \
do                                          \
{                                           \
    std::int64_t t0 = aeron_epoch_clock();  \
    while (!val)                            \
    {                                       \
       invoker.invoke();                    \
       ASSERT_LT(aeron_epoch_clock() - t0, AERON_TEST_TIMEOUT) << "Failed waiting for: "  << #op; \
       std::this_thread::yield();           \
       val = op;                            \
    }                                       \
}                                           \
while (0)                                   \

#define POLL_FOR(op, invoker)              \
do                                         \
{                                          \
    std::int64_t t0 = aeron_epoch_clock(); \
    while (!(op))                          \
    {                                      \
       invoker.invoke();                   \
       ASSERT_LT(aeron_epoch_clock() - t0, AERON_TEST_TIMEOUT) << "Failed waiting for: " << #op; \
       std::this_thread::yield();          \
    }                                      \
}                                          \
while (0)                                  \

#endif //AERON_TESTUTILS_H
