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

#ifndef AERON_TESTUTILS_H
#define AERON_TESTUTILS_H

#include <stdlib.h>
#include <util/Exceptions.h>
#include <command/Flyweight.h>

namespace aeron { namespace test {

command::BuffersReadyOsIpcDefn makeTempOsIpc()
{
    command::BuffersReadyOsIpcDefn osIpc;
    osIpc.bufferLength = 0;
    osIpc.bufferId = rand();
    osIpc.processId = -1;
}
inline void throwIllegalArgumentException()
{
    throw util::IllegalArgumentException("Intentional IllegalArgumentException", SOURCEINFO);
}

}}

#endif //AERON_TESTUTILS_H
