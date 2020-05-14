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

#ifndef AERON_FILEUTIL_H
#define AERON_FILEUTIL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "util/aeron_platform.h"
#include "command/aeron_control_protocol.h"

typedef struct aeron_mapped_file_stct
{
    void *addr;
    size_t length;
}
aeron_mapped_file_t;

typedef struct aeron_mapped_buffer_stct
{
    uint8_t *addr;
    size_t length;
}
aeron_mapped_buffer_t;

int aeron_is_directory(const char* path);
int aeron_delete_directory(const char* directory);
int64_t aeron_get_file_size(const char* filename);
int64_t aeron_get_pid();

int aeron_map_new_file(aeron_mapped_file_t *mapped_file, const char *path, bool fill_with_zeroes);
int aeron_map_existing_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, uint64_t offset, bool read_only);
int aeron_unmap(aeron_mapped_file_t *mapped_file);

#if defined(AERON_COMPILER_GCC)
#include <unistd.h>
#define aeron_mkdir mkdir
int aeron_ftruncate(int fd, uint64_t length);
#elif defined(AERON_COMPILER_MSVC)
int aeron_ftruncate(int fd, uint64_t length);
int aeron_mkdir(const char *path, int permission);
#endif

typedef struct aeron_image_os_ipc_mapped_stct
{
    aeron_image_os_ipc_command_t command;
#ifdef _WIN32
    void* handle;
#endif
}
aeron_image_os_ipc_mapped_t;

int aeron_map_new_os_ipc(aeron_mapped_file_t *mapped_file, aeron_image_os_ipc_mapped_t *os_ipc, uint64_t length, bool fill_with_zeroes);
int aeron_map_existing_os_ipc(aeron_mapped_file_t *mapped_file, aeron_image_os_ipc_command_t *os_ipc_command, bool read_only);
int aeron_close_os_ipc(aeron_image_os_ipc_mapped_t *os_ipc);

typedef uint64_t (*aeron_usable_fs_space_func_t)(const char *path);

int64_t aeron_file_length(const char *path);
uint64_t aeron_usable_fs_space(const char *path);
uint64_t aeron_usable_fs_space_disabled(const char *path);

void aeron_os_ipc_location(
    aeron_image_os_ipc_mapped_t *os_ipc,
    int64_t buffer_id);

void aeron_default_dir(char *target, size_t length);

#endif //AERON_FILEUTIL_H
