cd /d "%~dp0"

set "AERON_TERM_BUFFER_SPARSE_FILE=0"
set "AERON_MTU_LENGTH=60k"
set "AERON_SOCKET_SO_RCVBUF=2m"
set "AERON_SOCKET_SO_SNDBUF=2m"
set "AERON_RCV_INITIAL_WINDOW_LENGTH=2m"
set "AERON_THREADING_MODE=DEDICATED"
::-Daeron.dir=R:\Temp\aeron
aeronmd -Daeron.print.configuration=true -Daeron.socket.so_sndbuf=2m -Daeron.socket.so_rcvbuf=2m -Daeron.client.liveness.timeout=5s  -Daeron.dir.delete.on.start=1 -Daeron.dir.delete.on.shutdown=1 -Daeron.use.windows.high.res.timer=true
pause