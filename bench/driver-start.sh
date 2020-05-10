export AERON_TERM_BUFFER_SPARSE_FILE="0"
#export AERON_MTU_LENGTH="60000"
export AERON_RCV_INITIAL_WINDOW_LENGTH="2m"
export AERON_SOCKET_SO_RCVBUF="2m"
export AERON_SOCKET_SO_SNDBUF="2m"
export AERON_THREADING_MODE="DEDICATED"
export AERON_CONDUCTOR_IDLE_STRATEGY="spin"
export AERON_SENDER_IDLE_STRATEGY="yield"
export AERON_RECEIVER_IDLE_STRATEGY="yield"
# export AERON_NAME_RESOLVER_SUPPLIER="driver"
# -Daeron.socket.so_sndbuf=2m -Daeron.socket.so_rcvbuf=2m 
# -Daeron.term.buffer.length=67108864 
cd /home/aeron/binaries
pkill aeronmd
pkill java
pkill RateSubscriber
pkill StreamingPublisher
pkill Ping
pkill Pong
pkill rate_subscriber
pkill RoundtripPong
pkill RoundtripPong
pkill Bench
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
nohup ./aeronmd -Daeron.term.buffer.length=67108864 \
-Daeron.print.configuration=true \
-Daeron.dir.delete.on.start=true \
-Daeron.dir.delete.on.shutdown=true \
-Daeron.socket.multicast.ttl=32 \
</dev/null >aeronmd.log 2>&1 &

#-Daeron.driver.resolver.name=atos \
#-Daeron.driver.resolver.interface=192.168.199.1:0/24 \
#-Daeron.driver.resolver.bootstrap.neighbor=192.168.199.1:3333 \

#export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
#cd /home/aeron/aeron/aeron-samples/scripts/
#nohup ./low-latency-media-driver </dev/null >aeronmd.log 2>&1 &
echo "Finished start the driver "
