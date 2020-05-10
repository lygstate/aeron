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

typedef enum aeron_log_buffer_type_enum {
    AERON_LOG_BUFFER_TYPE_IPC = 0,
    AERON_LOG_BUFFER_TYPE_NETWORK = 1,
    AERON_LOG_BUFFER_TYPE_IMAGE = 2
} aeron_log_buffer_type_t;

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

int aeron_mmap(aeron_mapped_file_t *mapping, const char *filename, uint64_t size, uint64_t offset, bool read_only, bool creating_new);
int aeron_unmap(aeron_mapped_file_t *mapped_file);
int64_t aeron_file_length(const char *path);
uint64_t aeron_usable_fs_space(const char *path);
int aeron_delete_directory(const char* directory);
int aeron_is_directory(const char* path);

int aeron_unlink(const char *path);
int64_t aeron_get_pid();
int aeron_mkdir(const char *path, int permission);
void aeron_default_dir(char *target, size_t length);
int aeron_log_buffer_filename_create_direct(
    char* filename,
    size_t filename_max_length,
    int buffer_type, 
    int64_t buffer_id,
    uint64_t log_length
);
int aeron_log_buffer_filename_create(
    const char *aeron_dir,
    char* filename,
    size_t filename_max_length,
    int buffer_type, 
    int64_t buffer_id,
    int64_t term_length,
    size_t file_page_size);
int aeron_log_buffer_filename_delete(const char* filename);
int64_t aeron_log_buffer_file_length(const char* filename);
int aeron_map_new_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, bool fill_with_zeroes);
int aeron_map_existing_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, uint64_t offset, bool read_only);

typedef uint64_t (*aeron_usable_fs_space_func_t)(const char *path);

uint64_t aeron_usable_fs_space_disabled(const char *path);

#endif //AERON_FILEUTIL_H
