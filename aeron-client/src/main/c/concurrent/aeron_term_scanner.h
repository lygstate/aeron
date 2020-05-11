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

#ifndef AERON_TERM_SCANNER_H
#define AERON_TERM_SCANNER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "util/aeron_bitutil.h"
#include "protocol/aeron_udp_protocol.h"
#include "aeron_atomic.h"
#include "aeron_logbuffer_descriptor.h"

inline size_t aeron_term_scanner_scan_for_availability(
    const uint8_t *buffer, size_t term_length_left, size_t max_length, size_t *padding)
{
    const size_t limit = max_length < term_length_left ? max_length : term_length_left;
    size_t available = 0;
    size_t tmp_padding = 0;

    do
    {
        const uint8_t *ptr = buffer + available;
        const aeron_frame_header_t *frame_header = (aeron_frame_header_t *)ptr;

        int32_t frame_length;
        AERON_GET_VOLATILE(frame_length, frame_header->frame_length);
        if (0 >= frame_length)
        {
            break;
        }

        int32_t aligned_frame_length = AERON_ALIGN(frame_length, AERON_LOGBUFFER_FRAME_ALIGNMENT);
        if (AERON_HDR_TYPE_PAD == frame_header->type)
        {
            if (available > 0)
            {
                break;
            }
            tmp_padding = aligned_frame_length - AERON_DATA_HEADER_LENGTH;
            aligned_frame_length = AERON_DATA_HEADER_LENGTH;
        }

        available += aligned_frame_length;

        if (available > limit)
        {
            available -= aligned_frame_length;
            tmp_padding = 0;
            break;
        }
    }
    while (0 == tmp_padding && available < limit);

    *padding = tmp_padding;

    return available;
}

#endif //AERON_TERM_SCANNER_H
