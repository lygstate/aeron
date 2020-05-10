
#ifndef AERON_MAP_RAW_LOG_H
#define AERON_MAP_RAW_LOG_H

#include "aeron_fileutil.h"
#include "concurrent/aeron_logbuffer_descriptor.h"

int aeron_log_buffer_filename_create(
    const char *aeron_dir,
    char* filename,
    size_t filename_max_length,
    int buffer_type, 
    int64_t buffer_id,
    int64_t term_length,
    size_t file_page_size);

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

#endif /* AERON_MAP_RAW_LOG_H */
