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

#include <util/Exceptions.h>

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

}}

#endif //AERON_TESTUTILS_H
