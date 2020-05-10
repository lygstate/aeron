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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "util/aeron_platform.h"
#include "concurrent/aeron_logbuffer_descriptor.h"

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

int aeron_is_directory(const char *path);
int aeron_delete_directory(const char *directory);

int aeron_map_new_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, uint64_t offset, bool fill_with_zeroes);
int aeron_map_existing_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, uint64_t offset, bool read_only);
int aeron_mmap(aeron_mapped_file_t *mapping, const char *filename, uint64_t size, uint64_t offset, bool read_only, bool creating_new);
int aeron_unmap(aeron_mapped_file_t *mapped_file);

int aeron_unlink(const char *path);
int64_t aeron_get_pid();
int aeron_mkdir(const char *path, int permission);
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

typedef uint64_t (*aeron_usable_fs_space_func_t)(const char *path);

int64_t aeron_file_length(const char *path);
uint64_t aeron_usable_fs_space(const char *path);
uint64_t aeron_usable_fs_space_disabled(const char *path);

#define AERON_LOG_META_DATA_SECTION_INDEX (AERON_LOGBUFFER_PARTITION_COUNT)

typedef struct aeron_mapped_raw_log_stct
{
    aeron_mapped_buffer_t term_buffers[AERON_LOGBUFFER_PARTITION_COUNT];
    aeron_mapped_buffer_t log_meta_data;
    aeron_mapped_file_t mapped_file;
    size_t term_length;
}
aeron_mapped_raw_log_t;

#define AERON_PUBLICATIONS_DIR "publications"
#define AERON_IMAGES_DIR "images"

typedef int (*aeron_map_raw_log_func_t)(aeron_mapped_raw_log_t *, const char *, bool, uint64_t, uint64_t);
typedef int (*aeron_map_raw_log_close_func_t)(aeron_mapped_raw_log_t *, const char *filename);

int aeron_map_raw_log(
    aeron_mapped_raw_log_t *mapped_raw_log,
    const char *path,
    bool use_sparse_files,
    uint64_t term_length,
    uint64_t page_size);

int aeron_map_existing_log(
    aeron_mapped_raw_log_t *mapped_raw_log,
    const char *path,
    bool pre_touch);

int aeron_map_raw_log_close(aeron_mapped_raw_log_t *mapped_raw_log, const char *filename);

#endif //AERON_FILEUTIL_H
