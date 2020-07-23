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
#ifndef AERON_UTIL_MEMORY_MAPPED_FILE_H
#define AERON_UTIL_MEMORY_MAPPED_FILE_H

#include <cstdint>
#include <memory>
#include "util/Export.h"

extern "C"
{
#include "util/aeron_fileutil.h"
}

namespace aeron { namespace util
{

class CLIENT_EXPORT MemoryMappedFile
{
public:
    typedef std::shared_ptr<MemoryMappedFile> ptr_t;

    static ptr_t createNew(const char *filename, uint64_t offset, size_t length);
    static ptr_t mapExisting(const char *filename, uint64_t offset, size_t length, bool readOnly = false);
    static ptr_t mapExisting(const char *filename, bool readOnly = false);

    static void close(const char *filename);

    inline static ptr_t mapExistingReadOnly(const char *filename)
    {
        return mapExisting(filename, 0, 0, true);
    }

    ~MemoryMappedFile();

    std::uint8_t *getMemoryPtr() const;
    std::size_t getMemorySize() const;

    MemoryMappedFile(MemoryMappedFile const &) = delete;
    MemoryMappedFile& operator=(MemoryMappedFile const &) = delete;

    static std::size_t getPageSize() noexcept;
    static std::int64_t getFileSize(const char *filename);

private:

    MemoryMappedFile(const aeron_mapped_file_t &mapped_file);

    aeron_mapped_file_t mapped_file;
};

}}

#endif
