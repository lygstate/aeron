#include <stdio.h>
#include <inttypes.h>

#include "aeron_error.h"
#include "aeron_map_raw_log.h"

int aeron_log_buffer_filename_create(
    const char *aeron_dir,
    char* filename,
    size_t filename_max_length,
    int buffer_type, 
    int64_t buffer_id,
    int64_t term_length,
    size_t file_page_size)
{
    if (aeron_dir == NULL)
    {
        uint64_t log_length = aeron_logbuffer_compute_log_length((uint64_t)term_length, file_page_size);
        return aeron_log_buffer_filename_create_direct(filename, filename_max_length, buffer_type, buffer_id, log_length);
    }
    else
    {
        switch (buffer_type)
        {
            default:
                return -1;
            case AERON_LOG_BUFFER_TYPE_IPC:
            case AERON_LOG_BUFFER_TYPE_NETWORK:
                return snprintf(
                    filename, filename_max_length,
                    "%s/" AERON_PUBLICATIONS_DIR "-%" PRId64 ".logbuffer",
                    aeron_dir, buffer_id);
            case AERON_LOG_BUFFER_TYPE_IMAGE:
                return snprintf(
                    filename, filename_max_length,
                    "%s/" AERON_IMAGES_DIR "-%" PRId64 ".logbuffer",
                    aeron_dir, buffer_id);
        }
    }
}

int aeron_map_raw_log(
    aeron_mapped_raw_log_t *mapped_raw_log,
    const char *path,
    bool use_sparse_files,
    uint64_t term_length,
    uint64_t page_size)
{
    int result = -1;
    uint64_t log_length = aeron_logbuffer_compute_log_length(term_length, page_size);
    aeron_mapped_file_t *mapped_file = &mapped_raw_log->mapped_file;
    if (aeron_map_new_file(mapped_file, path, log_length, 0, !use_sparse_files) >= 0)
    {
       for (size_t i = 0; i < AERON_LOGBUFFER_PARTITION_COUNT; i++)
        {
            mapped_raw_log->term_buffers[i].addr = (uint8_t *)mapped_raw_log->mapped_file.addr + (i * term_length);
            mapped_raw_log->term_buffers[i].length = term_length;
        }

        mapped_raw_log->log_meta_data.addr =
            (uint8_t *)mapped_raw_log->mapped_file.addr + (log_length - AERON_LOGBUFFER_META_DATA_LENGTH);
        mapped_raw_log->log_meta_data.length = AERON_LOGBUFFER_META_DATA_LENGTH;
        mapped_raw_log->term_length = term_length;
        result = 0;
    }
    return result;
}

int aeron_map_existing_log(
    aeron_mapped_raw_log_t *mapped_raw_log,
    const char *path,
    bool pre_touch)
{
    int result = -1;

    if (aeron_map_existing_file(&mapped_raw_log->mapped_file, path, 0, 0, false) >= 0)
    {
        mapped_raw_log->log_meta_data.addr =
            (uint8_t *)mapped_raw_log->mapped_file.addr +
            (mapped_raw_log->mapped_file.length - AERON_LOGBUFFER_META_DATA_LENGTH);
        mapped_raw_log->log_meta_data.length = AERON_LOGBUFFER_META_DATA_LENGTH;

        aeron_logbuffer_metadata_t *log_meta_data = (aeron_logbuffer_metadata_t *)mapped_raw_log->log_meta_data.addr;
        size_t term_length = (size_t)log_meta_data->term_length;
        size_t page_size = (size_t)log_meta_data->page_size;

        if (aeron_logbuffer_check_term_length(term_length) < 0 ||
            aeron_logbuffer_check_page_size(page_size) < 0)
        {
            aeron_unmap(&mapped_raw_log->mapped_file);
            return -1;
        }

        mapped_raw_log->term_length = term_length;

        for (size_t i = 0; i < AERON_LOGBUFFER_PARTITION_COUNT; i++)
        {
            mapped_raw_log->term_buffers[i].addr = (uint8_t *)mapped_raw_log->mapped_file.addr + (i * term_length);
            mapped_raw_log->term_buffers[i].length = term_length;
        }

        if (pre_touch)
        {
            volatile int32_t value = 0;

            for (size_t i = 0; i < AERON_LOGBUFFER_PARTITION_COUNT; i++)
            {
                uint8_t *base_addr = mapped_raw_log->term_buffers[i].addr;

                for (size_t offset = 0; offset < term_length; offset += page_size)
                {
                    aeron_cmpxchg32((volatile int32_t *)(base_addr + offset), value, value);
                }
            }
        }

        result = 0;
    }
    else
    {
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }

    return result;
}

int aeron_map_raw_log_close(aeron_mapped_raw_log_t *mapped_raw_log, const char *filename)
{
    int result = 0;

    if (mapped_raw_log->mapped_file.addr != NULL)
    {
        mapped_raw_log->mapped_file.addr = NULL;
        if ((result = aeron_unmap(&mapped_raw_log->mapped_file)) < 0)
        {
            return -1;
        }

        if (NULL != filename && aeron_log_buffer_filename_delete(filename) < 0)
        {
            aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
            return -1;
        }
    }

    return result;
}

