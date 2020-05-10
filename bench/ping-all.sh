#!/bin/bash
cd /home/aeron/binaries
pkill Ping
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD

for (( i=$1; i<=$2; i++ ))
do
   PingStreamId=$i
   PongStreamId=$(( $i + 300 ))
   echo "Ping $PingStreamId $PongStreamId"
   ./Ping -c "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic|term-length=64k" -s $PingStreamId -C "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic|term-length=64k" -S $PongStreamId  -L 1024 -w 1000 -m 10000 -i 1 -e 1000 >ping_$PingStreamId.log &
done
