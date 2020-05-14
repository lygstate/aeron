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
#ifndef AERON_COMMAND_CONNECTION_READY_FLYWEIGHT_H
#define AERON_COMMAND_CONNECTION_READY_FLYWEIGHT_H

#include <cstdint>
#include <cstddef>
#include <util/BitUtil.h>
#include <util/Exceptions.h>
#include <util/StringUtil.h>
#include "Flyweight.h"

namespace aeron { namespace command
{

/**
* Message to denote that new buffers have been added for a subscription.
*
* NOTE: Layout should be SBE compliant
*
* @see ControlProtocolEvents
*
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 0
* |                       Correlation ID                          |
* |                                                               |
* +---------------------------------------------------------------+ 8
* |                         Session ID                            |
* +---------------------------------------------------------------+ 12
* |                         Stream ID                             |
* +---------------------------------------------------------------+ 16
* |                 Subscription Registration Id                  |
* |                                                               |
* +---------------------------------------------------------------+ 24
* |                    Subscriber Position Id                     |
* +---------------------------------------------------------------+ 28
* |                         Buffer Length                         |
* |                                                               |
* +---------------------------------------------------------------+ 36
* |                          Buffer Id                            |
* |                                                               |
* +---------------------------------------------------------------+ 44
* |                          Process Id                           |
* |                                                               |
* +---------------------------------------------------------------+ 52
* |                           Os Handle                           |
* |                                                               |
* +---------------------------------------------------------------+ 60
* |                    Source identity Length                     |
* +---------------------------------------------------------------+ 64
* |                    Source identity Name                      ...
*...                                                              |
* +---------------------------------------------------------------+
*/

#pragma pack(push)
#pragma pack(4)
struct ImageBuffersReadyDefn
{
    std::int64_t correlationId;
    std::int32_t sessionId;
    std::int32_t streamId;
    std::int64_t subscriptionRegistrationId;
    std::int32_t subscriberPositionId;
    aeron_image_os_ipc_t osIpc;
};
#pragma pack(pop)

class ImageBuffersReadyFlyweight : public Flyweight<ImageBuffersReadyDefn>
{
public:
    typedef ImageBuffersReadyFlyweight this_t;

    inline ImageBuffersReadyFlyweight(concurrent::AtomicBuffer &buffer, util::index_t offset) :
        Flyweight<ImageBuffersReadyDefn>(buffer, offset)
    {
    }

    inline std::int64_t correlationId() const
    {
        return m_struct.correlationId;
    }

    inline this_t &correlationId(std::int64_t value)
    {
        m_struct.correlationId = value;
        return *this;
    }

    inline std::int32_t sessionId() const
    {
        return m_struct.sessionId;
    }

    inline this_t &sessionId(std::int32_t value)
    {
        m_struct.sessionId = value;
        return *this;
    }

    inline std::int32_t streamId() const
    {
        return m_struct.streamId;
    }

    inline this_t &streamId(std::int32_t value)
    {
        m_struct.streamId = value;
        return *this;
    }

    inline std::int64_t subscriptionRegistrationId() const
    {
        return m_struct.subscriptionRegistrationId;
    }

    inline this_t &subscriberRegistrationId(std::int64_t value)
    {
        m_struct.subscriptionRegistrationId = value;
        return *this;
    }

    inline std::int32_t subscriberPositionId() const
    {
        return m_struct.subscriberPositionId;
    }

    inline this_t &subscriberPositionId(std::int32_t value)
    {
        m_struct.subscriberPositionId = value;
        return *this;
    }

    inline const aeron_image_os_ipc_t& osIpc() const
    {
        return m_struct.osIpc;
    }

    inline this_t &osIpc(const aeron_image_os_ipc_t &value)
    {
        m_struct.osIpc = value;
        return *this;
    }

    inline std::string sourceIdentity() const
    {
        return stringGet(sourceIdentityOffset());
    }

    inline this_t &sourceIdentity(const std::string &value)
    {
        stringPut(sourceIdentityOffset(), value);
        return *this;
    }

    inline std::int32_t length()
    {
        const util::index_t startOfSourceIdentity = sourceIdentityOffset();

        return static_cast<int32_t>(util::BitUtil::align(startOfSourceIdentity +
            stringGetLength(startOfSourceIdentity) +
            static_cast<util::index_t>(sizeof(std::int32_t)), 4));
    }

private:

    inline util::index_t sourceIdentityOffset() const
    {
        return sizeof(ImageBuffersReadyDefn);
    }
};

}}

#endif
