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

#define _DISABLE_EXTENDED_ALIGNED_STORAGE

#include "Aeron.h"
#include "CncFileDescriptor.h"

using namespace aeron;
using namespace aeron::util;

void Context::requestDriverTermination(
    const std::string &directory, const std::uint8_t *tokenBuffer, std::size_t tokenLength,  long timeout_ms)
{
    const std::string cncFilename = directory + AERON_PATH_SEP + CncFileDescriptor::CNC_FILE;
    MemoryMappedFile::ptr_t cncFile = Aeron::mapCncFile(cncFilename, timeout_ms);
    if (!cncFile)
    {
        return;
    }

    AtomicBuffer toDriverBuffer(CncFileDescriptor::createToDriverBuffer(cncFile));
    ManyToOneRingBuffer ringBuffer(toDriverBuffer);
    DriverProxy driverProxy(ringBuffer);

    driverProxy.terminateDriver(tokenBuffer, tokenLength);
}
