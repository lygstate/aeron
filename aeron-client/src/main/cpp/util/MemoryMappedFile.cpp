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


#include <string>
#include <cstring>

#include "MemoryMappedFile.h"
#include "Exceptions.h"
#include "ScopeUtils.h"
extern "C"
{
#include <util/aeron_error.h>
}

namespace aeron { namespace util
{

MemoryMappedFile::ptr_t MemoryMappedFile::createNew(const char* filename)
{
    aeron_mapped_file_t mapped_file;
    if (aeron_map_new_file(&mapped_file, filename, 0, true) < 0)
    {
        throw IOException(std::string("Failed to MemoryMappedFile::createNew file: ") + filename + " " + aeron_errmsg(), SOURCEINFO);
    }

    auto obj = MemoryMappedFile::ptr_t(new MemoryMappedFile(mapped_file));
    return obj;
}

MemoryMappedFile::ptr_t MemoryMappedFile::mapExisting(const char* filename, uint64_t offset, size_t length, bool readOnly)
{
    aeron_mapped_file_t mapped_file;
    if (aeron_map_existing_file(&mapped_file, filename, length, offset, readOnly) < 0)
    {
        throw IOException(std::string("Failed to MemoryMappedFile::mapExisting file: ") + filename + " " + aeron_errmsg(), SOURCEINFO);
    }
    auto obj = MemoryMappedFile::ptr_t(new MemoryMappedFile(mapped_file));
    return obj;
}

MemoryMappedFile::ptr_t MemoryMappedFile::mapExisting(const char* filename, bool readOnly)
{
    return mapExisting(filename, 0, 0, readOnly);
}

void MemoryMappedFile::close(const char* filename)
{
    aeron_log_buffer_filename_delete(filename);
}

uint8_t* MemoryMappedFile::getMemoryPtr() const
{
    return (uint8_t*)mapped_file.addr;
}

size_t MemoryMappedFile::getMemorySize() const
{
    return mapped_file.length;
}

std::int64_t MemoryMappedFile::getFileSize(const char *filename)
{
    return aeron_log_buffer_file_length(filename);
}

MemoryMappedFile::MemoryMappedFile(const aeron_mapped_file_t &_mapped_file):
    mapped_file(_mapped_file)
{
}

MemoryMappedFile::~MemoryMappedFile()
{
    aeron_unmap(&mapped_file);
}

}}
