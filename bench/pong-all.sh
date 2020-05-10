#!/bin/bash
cd /home/aeron/binaries
pkill Pong
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD

for (( i=$1; i<=$2; i++ ))
do
   PingStreamId=$i
   PongStreamId=$(( $i + 300 ))
   echo "Pong $PingStreamId $PongStreamId"
   ./Pong -c "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic|term-length=64k" -s $PingStreamId -C "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic|term-length=64k" -S $PongStreamId &
done
