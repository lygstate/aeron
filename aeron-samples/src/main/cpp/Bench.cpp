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

#include <cstdint>
#include <csignal>
#include <thread>
#include <chrono>

#define __STDC_FORMAT_MACROS

extern "C"
{
#include <hdr_histogram.h>
}

#include "concurrent/BackOffIdleStrategy.h"
#include "concurrent/BusySpinIdleStrategy.h"
#include "concurrent/YieldingIdleStrategy.h"
#include "FragmentAssembler.h"
#include "Configuration.h"
#include "Aeron.h"

using namespace std::chrono;
using namespace aeron::util;
using namespace aeron;

std::atomic<bool> running(true);

void sigIntHandler(int param)
{
    running = false;
}

struct Settings
{
    bool isPing = false; // otherwise is pong;
    std::string dirPrefix = "";
    std::string pingChannel = samples::configuration::DEFAULT_PING_CHANNEL;
    std::string pongChannel = samples::configuration::DEFAULT_PONG_CHANNEL;
    std::int32_t pingStreamId = samples::configuration::DEFAULT_PING_STREAM_ID;
    std::int32_t pongStreamId = samples::configuration::DEFAULT_PONG_STREAM_ID;
    int fragmentCountLimit = samples::configuration::DEFAULT_FRAGMENT_COUNT_LIMIT;
    std::string idle = "spin";

    std::int64_t numberOfWarmupMessages = samples::configuration::DEFAULT_NUMBER_OF_WARM_UP_MESSAGES;
    std::int64_t numberOfMessages = samples::configuration::DEFAULT_NUMBER_OF_MESSAGES;
    int messageLength = samples::configuration::DEFAULT_MESSAGE_LENGTH;
    std::uint32_t sleepTime = 32;
};

void sendPingAndReceivePong(
    const fragment_handler_t &fragmentHandler,
    std::vector<std::shared_ptr<ExclusivePublication>> &pingPublicationList,
    std::vector<std::shared_ptr<Subscription>> &pongSubscriptionList,
    const Settings &settings)
{
    std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[settings.messageLength]);
    concurrent::AtomicBuffer srcBuffer(buffer.get(), static_cast<size_t>(settings.messageLength));
    BusySpinIdleStrategy idleStrategy;
    std::vector<std::shared_ptr<Image>> pongSubscriptionImageList;
    for (size_t i = 0; i < pongSubscriptionList.size(); i += 1)
    {
        std::shared_ptr<Image> imageSharedPtr = pongSubscriptionList[i]->imageByIndex(0);
        pongSubscriptionImageList.push_back(imageSharedPtr);
    }
    static const std::chrono::duration<long, std::micro> sleep_us_duration(settings.sleepTime);

    int handleIndex = 0;
    for (long i = 0; i < settings.numberOfMessages; i++)
    {
        ExclusivePublication &publication = *pingPublicationList[handleIndex];
        Image &image = *pongSubscriptionImageList[handleIndex];
        std::int64_t position = image.position();
        idleStrategy.reset();

        do
        {
            if (position < 0L)
            {
                idleStrategy.idle();
            }
            // timestamps in the message are relative to this app, so just send the timestamp directly.
            steady_clock::time_point start = steady_clock::now();

            srcBuffer.putBytes(0, (std::uint8_t *)&start, sizeof(steady_clock::time_point));
            position = publication.offer(srcBuffer, 0, settings.messageLength);
        }
        while (position < 0L);

        idleStrategy.reset();
        do
        {
            while (image.poll(fragmentHandler, settings.fragmentCountLimit) <= 0)
            {
                idleStrategy.idle();
            }
        }
        while (image.position() < position);

#if 0
        printf("wait ack finished position:%lld handleIndex:%d\n", (long long)image.position(), handleIndex);
        fflush(stdout);
#endif

        if (settings.sleepTime > 0)
        {
            std::this_thread::sleep_for(sleep_us_duration);
        }
        handleIndex = (handleIndex + 1) % pingPublicationList.size();
    }
}

void Ping(const Settings& settings, int pingCount)
{
    aeron::Context context;
    std::atomic<int> countDown(pingCount);
    std::vector<std::int64_t> subscriptionIdList;
    std::vector<std::int64_t> publicationIdList;

    if (!settings.dirPrefix.empty())
    {
        context.aeronDir(settings.dirPrefix);
    }

    context.newSubscriptionHandler(
        [](const std::string &channel, std::int32_t streamId, std::int64_t correlationId)
        {
            std::cout << "Subscription: " << channel << " " << correlationId << ":" << streamId << std::endl;
        });

    context.newPublicationHandler(
        [](const std::string &channel, std::int32_t streamId, std::int32_t sessionId, std::int64_t correlationId)
        {
            std::cout << "Publication: " << channel << " " << correlationId << ":" << streamId << ":" << sessionId << std::endl;
        });

    context.availableImageHandler(
        [&](Image &image)
        {
            std::cout << "Available image correlationId=" << image.correlationId() << " sessionId=" << image.sessionId();
            std::cout << " at position=" << image.position() << " from " << image.sourceIdentity() << std::endl;
            auto itr = std::find(subscriptionIdList.begin(), subscriptionIdList.end(), image.subscriptionRegistrationId());
            if (itr != subscriptionIdList.end())
            {
                countDown--;
            }
        });

    context.unavailableImageHandler(
        [](Image &image)
        {
            std::cout << "Unavailable image on correlationId=" << image.correlationId() << " sessionId=" << image.sessionId();
            std::cout << " at position=" << image.position() << " from " << image.sourceIdentity() << std::endl;
        });

    context.preTouchMappedMemory(true);

    Aeron aeron(context);
    for (int i = 0; i < pingCount; i += 1)
    {
        int pingStreamId = settings.pingStreamId + i;
        int pongStreamId = settings.pongStreamId + i;
        std::cout << "Subscribing Pong at " << settings.pongChannel << " on Stream ID " << pongStreamId << std::endl;
        std::cout << "Publishing Ping at " << settings.pingChannel << " on Stream ID " << pingStreamId << std::endl;
        subscriptionIdList.push_back(aeron.addSubscription(settings.pongChannel, pongStreamId));
        publicationIdList.push_back(aeron.addExclusivePublication(settings.pingChannel, pingStreamId));
    }

    std::vector<std::shared_ptr<Subscription>> pongSubscriptionList;
    std::vector<std::shared_ptr<ExclusivePublication>> pingPublicationList;
    pongSubscriptionList.resize(pingCount);
    pingPublicationList.resize(pingCount);
    bool foundAllPingPong = false;
    while (!foundAllPingPong)
    {
        foundAllPingPong = true;
        for (int i = 0; i < pingCount; i += 1)
        {
            if (!pongSubscriptionList[i]) {
                foundAllPingPong = false;
                auto subscription = aeron.findSubscription(subscriptionIdList[i]);
                pongSubscriptionList[i] = subscription;
            }

            if (!pingPublicationList[i]) {
                foundAllPingPong = false;
                auto publication = aeron.findExclusivePublication(publicationIdList[i]);
                pingPublicationList[i] = publication;
            }
        }
        std::this_thread::sleep_for(std::chrono::duration<long, std::micro>(10));
    }

    while (countDown > 0)
    {
        std::this_thread::sleep_for(std::chrono::duration<long, std::micro>(10));
    }

    if (settings.numberOfWarmupMessages > 0)
    {
        Settings warmupSettings = settings;
        warmupSettings.numberOfMessages = warmupSettings.numberOfWarmupMessages;

        const steady_clock::time_point start = steady_clock::now();

        std::cout << "Warming up the media driver with "
                    << toStringWithCommas(warmupSettings.numberOfWarmupMessages) << " messages of length "
                    << toStringWithCommas(warmupSettings.messageLength) << std::endl;

        sendPingAndReceivePong(
            [](AtomicBuffer&, index_t, index_t, Header&){}, pingPublicationList, pongSubscriptionList, warmupSettings);

        std::int64_t nanoDuration = duration<std::int64_t, std::nano>(steady_clock::now() - start).count();

        std::cout << "Warmed up the media driver in " << nanoDuration << " [ns]" << std::endl;
    }

    hdr_histogram *histogram;
    hdr_init(1, 10 * 1000 * 1000 * 1000LL, 3, &histogram);

    for (;;)
    {
        hdr_reset(histogram);

        FragmentAssembler fragmentAssembler(
            [&](const AtomicBuffer &buffer, index_t offset, index_t length, const Header &header)
            {
                steady_clock::time_point end = steady_clock::now();
                steady_clock::time_point start;

                buffer.getBytes(offset, (std::uint8_t *)&start, sizeof(steady_clock::time_point));
                std::int64_t nanoRtt = duration<std::int64_t, std::nano>(end - start).count();

                hdr_record_value(histogram, nanoRtt);
            });

        std::cout << "Pinging "
                    << toStringWithCommas(settings.numberOfMessages) << " messages of length "
                    << toStringWithCommas(settings.messageLength) << " bytes" << std::endl;

        sendPingAndReceivePong(fragmentAssembler.handler(), pingPublicationList, pongSubscriptionList, settings);

        hdr_percentiles_print(histogram, stdout, 5, 1000.0, CLASSIC);
        fflush(stdout);
        if (!running)
        {
            break;
        }
    }
}

void Pong(const Settings& settings)
{
    aeron::Context context;

    if (!settings.dirPrefix.empty())
    {
        context.aeronDir(settings.dirPrefix);
    }

    context.newSubscriptionHandler(
        [](const std::string &channel, std::int32_t streamId, std::int64_t correlationId)
        {
            std::cout << "Subscription: " << channel << " " << correlationId << ":" << streamId << std::endl;
        });

    context.newPublicationHandler(
        [](const std::string &channel, std::int32_t streamId, std::int32_t sessionId, std::int64_t correlationId)
        {
            std::cout << "Publication: " << channel << " " << correlationId << ":" << streamId << ":" << sessionId << std::endl;
        });

    context.availableImageHandler(
        [](Image &image)
        {
            std::cout << "Available image correlationId=" << image.correlationId() << " sessionId=" << image.sessionId();
            std::cout << " at position=" << image.position() << " from " << image.sourceIdentity() << std::endl;
        });

    context.unavailableImageHandler(
        [](Image &image)
        {
            std::cout << "Unavailable image on correlationId=" << image.correlationId() << " sessionId=" << image.sessionId();
            std::cout << " at position=" << image.position() << " from " << image.sourceIdentity() << std::endl;
        });

    context.preTouchMappedMemory(true);

    Aeron aeron(context);

    std::int64_t subscriptionId = aeron.addSubscription(settings.pingChannel, settings.pingStreamId);
    std::int64_t publicationId = aeron.addExclusivePublication(settings.pongChannel, settings.pongStreamId);

    std::shared_ptr<Subscription> pingSubscription = aeron.findSubscription(subscriptionId);
    while (!pingSubscription)
    {
        std::this_thread::yield();
        pingSubscription = aeron.findSubscription(subscriptionId);
    }

    std::shared_ptr<ExclusivePublication> pongPublication = aeron.findExclusivePublication(publicationId);
    while (!pongPublication)
    {
        std::this_thread::yield();
        pongPublication = aeron.findExclusivePublication(publicationId);
    }

    ExclusivePublication &pongPublicationRef = *pongPublication;
    Subscription &pingSubscriptionRef = *pingSubscription;

#if 0
    BackoffIdleStrategy idleStrategy(256, 32,
        std::chrono::duration<long, std::micro>(1),
        std::chrono::duration<long, std::micro>(8)
    );
#endif
    YieldingIdleStrategy idleStrategy;
    BusySpinIdleStrategy pingHandlerIdleStrategy;
    FragmentAssembler fragmentAssembler(
        [&](AtomicBuffer &buffer, index_t offset, index_t length, const Header &header)
        {
            if (pongPublicationRef.offer(buffer, offset, length) > 0L)
            {
                return;
            }

            pingHandlerIdleStrategy.reset();
            while (pongPublicationRef.offer(buffer, offset, length) < 0L)
            {
                pingHandlerIdleStrategy.idle();
            }
        });

    fragment_handler_t handler = fragmentAssembler.handler();

    while (running)
    {
        idleStrategy.idle(pingSubscriptionRef.poll(handler, settings.fragmentCountLimit));
    }

    std::cout << "Shutting down...\n";
}

int main(int argc, char **argv)
{
    signal(SIGINT, sigIntHandler);

    try
    {
        Settings settings;
        settings.pingChannel = "aeron:ipc?term-length=64k";
        settings.pongChannel = "aeron:ipc?term-length=64k";
        settings.messageLength = 1024;
        if (strcmp(getenv("IS_UDP"), "true") == 0)
        {
            settings.pingChannel = "aeron:udp?endpoint=localhost:20123|term-length=64k";
            settings.pongChannel = "aeron:udp?endpoint=localhost:20124|term-length=64k";
        }

        if (strcmp(getenv("IS_PING"), "true") == 0)
        {
            settings.isPing = true;
        }

        settings.pingStreamId = atol(getenv("PING_STREAM_ID"));
        settings.pongStreamId = settings.pingStreamId + 1000;
        int32_t stream_count = atol(getenv("PING_STREAM_COUNT"));

        if (settings.isPing)
        {
            Ping(settings, stream_count);
        }
        else
        {
            Pong(settings);
        }
    }
    catch (const SourcedException &e)
    {
        std::cerr << "FAILED: " << e.what() << " : " << e.where() << std::endl;
        return -1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "FAILED: " << e.what() << " : " << std::endl;
        return -1;
    }

    return 0;
}
