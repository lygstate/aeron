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
#include "util/aeron_error.h"
}

namespace aeron { namespace util
{

MemoryMappedFile::ptr_t MemoryMappedFile::createNew(aeron_image_os_ipc_t &osIpc, uint64_t offset, size_t size)
{
    aeron_mapped_file_t mapped_file;
    if (aeron_map_new_os_ipc(&mapped_file, &osIpc, size, true) < 0)
    {
        throw IOException(std::string("Failed to create file buffer id: ") + toString(osIpc.buffer_id) + " " + aeron_errmsg(), SOURCEINFO);
    }

    auto obj = MemoryMappedFile::ptr_t(new MemoryMappedFile(mapped_file));
    return obj;
}

MemoryMappedFile::ptr_t MemoryMappedFile::mapExisting(const char *filename, uint64_t offset, size_t size, bool readOnly)
{
    aeron_mapped_file_t mapped_file;
    if (aeron_map_existing_file(&mapped_file, filename, size, offset, readOnly) < 0)
    {
        throw IOException(std::string("Failed to create file: ") + filename + " " + aeron_errmsg(), SOURCEINFO);
    }
    auto obj = MemoryMappedFile::ptr_t(new MemoryMappedFile(mapped_file));
    return obj;
}

MemoryMappedFile::ptr_t MemoryMappedFile::mapExisting(const aeron_image_os_ipc_t &osIpc)
{
    aeron_mapped_file_t mapped_file;
    if (aeron_map_existing_os_ipc(&mapped_file, (const aeron_image_os_ipc_t *)&osIpc, true) < 0)
    {
        throw IOException(std::string("Failed to create file buffer id: ") + toString(osIpc.buffer_id) + " " + aeron_errmsg(), SOURCEINFO);
    }

    auto obj = MemoryMappedFile::ptr_t(new MemoryMappedFile(mapped_file));
    return obj;
}

void MemoryMappedFile::close(aeron_image_os_ipc_t &osIpc)
{
    aeron_close_os_ipc(&osIpc);
}

MemoryMappedFile::ptr_t MemoryMappedFile::mapExisting(const char *filename, bool readOnly)
{
    return mapExisting(filename, 0, 0, readOnly);
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
    return aeron_file_length(filename);
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
