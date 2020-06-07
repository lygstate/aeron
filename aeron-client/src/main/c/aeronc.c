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

#if defined(__linux__)
#define _BSD_SOURCE
#define _GNU_SOURCE
#ifdef HAVE_BSDSTDLIB_H
#include <bsd/stdlib.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "aeron_common.h"
#include "util/aeron_bitutil.h"
#include "util/aeron_fileutil.h"
#include "aeronc.h"
#include "aeron_context.h"
#include "util/aeron_error.h"
#include "aeron_cnc_file_descriptor.h"
#include "concurrent/aeron_mpsc_rb.h"

int aeron_client_connect_to_driver(aeron_mapped_file_t *cnc_mmap, aeron_context_t *context)
{
    long long start_ms = context->epoch_clock();
    long long deadline_ms = start_ms + context->driver_timeout_ms;
    char filename[AERON_MAX_PATH];

#if defined(_MSC_VER)
    snprintf(filename, sizeof(filename) - 1, "%s\\" AERON_CNC_FILE, context->aeron_dir);
#else
    snprintf(filename, sizeof(filename) - 1, "%s/" AERON_CNC_FILE, context->aeron_dir);
#endif

    while (true)
    {
        while ((size_t)aeron_file_length(filename) <= sizeof(aeron_cnc_metadata_t))
        {
            if (context->epoch_clock() > deadline_ms)
            {
                aeron_set_err(ETIMEDOUT, "CnC file not created: %s", filename);
                return -1;
            }

            aeron_micro_sleep(16 * 1000);
        }

        if (aeron_map_existing_file(cnc_mmap, filename) < 0)
        {
            aeron_set_err(aeron_errcode(), "CnC file could not be mmapped: %s", aeron_errmsg());
            return -1;
        }

        aeron_cnc_metadata_t *metadata = (aeron_cnc_metadata_t *)cnc_mmap->addr;
        int32_t cnc_version;

        while (0 == (cnc_version = aeron_cnc_version_volatile(metadata)))
        {
            if (context->epoch_clock() > deadline_ms)
            {
                aeron_set_err(ETIMEDOUT, "CnC file is created but not initialised");
                aeron_unmap(cnc_mmap);
                return -1;
            }

            aeron_micro_sleep(1000);
        }

        if (aeron_semantic_version_major(AERON_CNC_VERSION) != aeron_semantic_version_major(cnc_version))
        {
            aeron_set_err(EINVAL, "CnC version not compatible: app=%d.%d.%d file=%d.%d.%d",
                (int)aeron_semantic_version_major(AERON_CNC_VERSION),
                (int)aeron_semantic_version_minor(AERON_CNC_VERSION),
                (int)aeron_semantic_version_patch(AERON_CNC_VERSION),
                (int)aeron_semantic_version_major(cnc_version),
                (int)aeron_semantic_version_minor(cnc_version),
                (int)aeron_semantic_version_patch(cnc_version));
            aeron_unmap(cnc_mmap);
            return -1;
        }

        /* make sure the cnc.dat have valid file length before init mpsc */
        while (true)
        {
            size_t total_length_of_buffers = (size_t)(metadata->to_driver_buffer_length +
                    metadata->to_clients_buffer_length +
                    metadata->counter_values_buffer_length +
                    metadata->counter_metadata_buffer_length +
                    metadata->error_log_buffer_length);
            int64_t file_size_computed = (int64_t)aeron_cnc_computed_length(
                total_length_of_buffers,
                context->file_page_size);
            if (aeron_file_length(filename) == file_size_computed)
            {
                /* Remapping the file */
                if (file_size_computed != (int64_t)cnc_mmap->length)
                {
                    aeron_unmap(cnc_mmap);
                    if (aeron_map_existing_file(cnc_mmap, filename) < 0)
                    {
                        aeron_set_err(aeron_errcode(), "CnC file could not be mmapped: %s", aeron_errmsg());
                        return -1;
                    }
                    metadata = (aeron_cnc_metadata_t *)cnc_mmap->addr;
                }
                break;
            }
            if (context->epoch_clock() > deadline_ms)
            {
                aeron_set_err(ETIMEDOUT, "CnC file is created but not initialised with enough length");
                aeron_unmap(cnc_mmap);
                return -1;
            }
            aeron_micro_sleep(1000);
        }

        aeron_mpsc_rb_t rb;

        if (aeron_mpsc_rb_init(
            &rb, aeron_cnc_to_driver_buffer(metadata), (size_t)metadata->to_driver_buffer_length) != 0)
        {
            aeron_set_err(aeron_errcode(), "CnC file to-driver ring buffer: %s", aeron_errmsg());
            aeron_unmap(cnc_mmap);
            return -1;
        }

        while (0 == aeron_mpsc_rb_consumer_heartbeat_time_value(&rb))
        {
            if (context->epoch_clock() > deadline_ms)
            {
                aeron_set_err(ETIMEDOUT, "no driver heartbeat detected");
                aeron_unmap(cnc_mmap);
                return -1;
            }

            aeron_micro_sleep(1000);
        }

        long long now_ms = context->epoch_clock();
        if (aeron_mpsc_rb_consumer_heartbeat_time_value(&rb) < (now_ms - (long long)context->driver_timeout_ms))
        {
            if (now_ms > deadline_ms)
            {
                aeron_set_err(ETIMEDOUT, "no driver heartbeat detected");
                aeron_unmap(cnc_mmap);
                return -1;
            }

            aeron_unmap(cnc_mmap);

            aeron_micro_sleep(100 * 1000);
            continue;
        }

        break;
    }

    return 0;
}
