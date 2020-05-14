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

#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <util/Index.h>
#include <util/BitUtil.h>
#include <concurrent/AtomicBuffer.h>
#include <command/ImageMessageFlyweight.h>
#include <command/ImageBuffersReadyFlyweight.h>
#include <command/RemoveMessageFlyweight.h>
#include <command/SubscriptionMessageFlyweight.h>
#include <command/PublicationMessageFlyweight.h>
#include <command/PublicationBuffersReadyFlyweight.h>
#include <command/CounterMessageFlyweight.h>

using namespace aeron::util;
using namespace aeron::command;
using namespace aeron::concurrent;

static std::array<std::uint8_t, 1024> testBuffer;

static void clearBuffer()
{
    testBuffer.fill(0);
}

TEST (commandTests, testInstantiateFlyweights)
{
    clearBuffer();
    AtomicBuffer ab (&testBuffer[0], testBuffer.size());
    const index_t BASE_OFFSET = 256;

    std::string channelData = "channelData";

    ASSERT_NO_THROW({
        ImageMessageFlyweight cmd(ab, BASE_OFFSET);
    });

    ASSERT_NO_THROW({
        ImageBuffersReadyFlyweight cmd(ab, BASE_OFFSET);
    });

    ASSERT_NO_THROW({
        RemoveMessageFlyweight cmd(ab, BASE_OFFSET);
    });

    ASSERT_NO_THROW({
        SubscriptionMessageFlyweight cmd(ab, BASE_OFFSET);
    });

    ASSERT_NO_THROW({
        PublicationMessageFlyweight cmd(ab, BASE_OFFSET);
    });

    ASSERT_NO_THROW({
        PublicationBuffersReadyFlyweight cmd(ab, BASE_OFFSET);
    });

    ASSERT_NO_THROW({
        CounterMessageFlyweight cmd(ab, BASE_OFFSET);
    });
}

TEST (commandTests, testImageMessageFlyweight)
{
    clearBuffer();
    AtomicBuffer ab (&testBuffer[0], testBuffer.size());
    const index_t BASE_OFFSET = 256;

    std::string channelData = "channelData";

    ASSERT_NO_THROW({
        ImageMessageFlyweight cmd (ab, BASE_OFFSET);
        cmd.correlationId(1).subscriptionRegistrationId(2).streamId(3).channel(channelData);

        ASSERT_EQ(ab.getInt64(BASE_OFFSET + 0), 1);
        ASSERT_EQ(ab.getInt64(BASE_OFFSET + 8), 2);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 16), 3);
        ASSERT_EQ(ab.getString(BASE_OFFSET + 20), channelData);

        ASSERT_EQ(cmd.correlationId(), 1);
        ASSERT_EQ(cmd.streamId(), 3);
        ASSERT_EQ(cmd.channel(), channelData);

        ASSERT_EQ(cmd.length(), static_cast<int>(20 + sizeof(std::int32_t) + channelData.length()));
    });
}


TEST (commandTests, testPublicationReadyFlyweight)
{
    clearBuffer();
    AtomicBuffer ab(&testBuffer[0], testBuffer.size());
    const index_t BASE_OFFSET = 256;

    BuffersReadyOsIpcDefn osIpc;
    osIpc.bufferLength = 1023;
    osIpc.bufferId = 133;
    osIpc.processId = 123;

    ASSERT_NO_THROW({
        PublicationBuffersReadyFlyweight cmd(ab, BASE_OFFSET);

        cmd.correlationId(-1).registrationId(1).streamId(0x01010101).sessionId(0x02020202).positionLimitCounterId(10);
        cmd.channelStatusIndicatorId(11);
        cmd.osIpc(osIpc);

        ASSERT_EQ(ab.getInt64(BASE_OFFSET + 0), -1);
        ASSERT_EQ(ab.getInt64(BASE_OFFSET + 8), 1);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 16), 0x02020202);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 20), 0x01010101);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 24), 10);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 28), 11);
        ASSERT_EQ(ab.getInt64(BASE_OFFSET + 333), osIpc.bufferLength);

        ASSERT_EQ(cmd.correlationId(), -1);
        ASSERT_EQ(cmd.registrationId(), 1);
        ASSERT_EQ(cmd.streamId(), 0x01010101);
        ASSERT_EQ(cmd.sessionId(), 0x02020202);
        ASSERT_EQ(cmd.positionLimitCounterId(), 10);
        ASSERT_EQ(cmd.osIpc(), osIpc);

        ASSERT_EQ(cmd.length(), static_cast<int>(32 + 24));
    });
}

TEST (commandTests, testImageBuffersReadyFlyweight)
{
    clearBuffer();
    AtomicBuffer ab(&testBuffer[0], testBuffer.size());
    const index_t BASE_OFFSET = 0;

    BuffersReadyOsIpcDefn osIpc;
    osIpc.bufferLength = 1029;
    osIpc.bufferId = 135;
    osIpc.processId = 126;

    std::string sourceInfoData = "sourceinfodata";

    ASSERT_NO_THROW({
        ImageBuffersReadyFlyweight cmd(ab, BASE_OFFSET);

        cmd.correlationId(-1);

        cmd.sessionId(0x02020202)
            .streamId(0x01010101)
            .subscriberRegistrationId(2)
            .subscriberPositionId(1)
            .osIpc(osIpc)
            .sourceIdentity(sourceInfoData);

        ASSERT_EQ(ab.getInt64(BASE_OFFSET + 0), -1);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 8), 0x02020202);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 12), 0x01010101);

        ASSERT_EQ(ab.getInt64(BASE_OFFSET + 16), 2);
        ASSERT_EQ(ab.getInt32(BASE_OFFSET + 24), 1);

        const index_t startOfSourceIdentityAligned = 32 + 24;
        ASSERT_EQ(ab.getStringLength(startOfSourceIdentityAligned), static_cast<int>(sourceInfoData.length()));
        ASSERT_EQ(ab.getString(startOfSourceIdentityAligned), sourceInfoData);

        ASSERT_EQ(cmd.correlationId(), -1);
        ASSERT_EQ(cmd.sessionId(), 0x02020202);
        ASSERT_EQ(cmd.streamId(), 0x01010101);
        ASSERT_EQ(cmd.subscriptionRegistrationId(), 2);
        ASSERT_EQ(cmd.subscriberPositionId(), 1);
        ASSERT_EQ(cmd.osIpc(), osIpc);
        ASSERT_EQ(cmd.sourceIdentity(), sourceInfoData);

        size_t expectedLengthRaw = 32 + 24 + sizeof(std::int32_t) + sourceInfoData.length();
        int32_t expectedLength = static_cast<int32_t>(BitUtil::align(static_cast<index_t>(expectedLengthRaw), 4));

        ASSERT_EQ(cmd.length(), expectedLength);
    });
}

TEST (commandTests, testCounterMessageFlyweight)
{
    clearBuffer();
    AtomicBuffer ab(&testBuffer[0], testBuffer.size());

    std::array<std::uint8_t, 29> keyBuffer = {};
    keyBuffer.fill(1);
    std::string label = "this is very cool label";

    ASSERT_NO_THROW({
        CounterMessageFlyweight cmd(ab, 16);

        cmd.correlationId(42).clientId(-9);

        cmd.typeId(36)
            .keyBuffer(keyBuffer.data(), keyBuffer.size())
            .label(label);

        ASSERT_EQ(cmd.correlationId(), 42);
        ASSERT_EQ(cmd.clientId(), -9);
        ASSERT_EQ(cmd.typeId(), 36);
        ASSERT_EQ(cmd.keyLength(), 29);
        const uint8_t* srcBuffer = keyBuffer.data();
        const uint8_t* writtenBuffer = cmd.keyBuffer();
        ASSERT_TRUE( 0 == std::memcmp( srcBuffer, writtenBuffer, 29 ) );
        ASSERT_EQ(cmd.labelLength(), static_cast<int>(label.size()));
        ASSERT_EQ(cmd.label(), label);

        const int expectedLength = static_cast<int>(
                sizeof(std::int64_t) * 2 + sizeof(std::int32_t) * 2 + BitUtil::align(29, 4) + sizeof(std::int32_t) + label.length());

        ASSERT_EQ(cmd.length(), expectedLength);
    });
}
