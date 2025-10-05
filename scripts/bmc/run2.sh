#!/bin/bash
set -e

# Make sure we can create many sockets
if [ "$(ulimit -n)" -lt 16384 ]; then
	echo "Increase limit on the number of open files/sockets (ulimit -n)"
	ulimit -n 65536
	if [ $? -ne 0 ]; then
		echo "Failed to increase the limit"
		exit 1
	fi
fi

SERVER_HOST=192.168.1.1
SERVER_PORT=11211
SERVER_UDP_PORT=11211
# NOTE: Experiment duration in seconds
TIME=600
REPEAT=1
LOG_FILE=/tmp/bmc_performance.txt

LOCALHOST=`hostname`
AGENT=$LOCALHOST
NUM_AGENTS=24
CONN_PER_AGENT=32

# COUNT_RECORDS=1
# COUNT_RECORDS=1000
# COUNT_RECORDS=100000
# COUNT_RECORDS=300000
COUNT_RECORDS=500000
# COUNT_RECORDS=1000000

WRK="twitter"
case $WRK in
  facebook)
    WORKLOAD_DESC="--records=$COUNT_RECORDS --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0"
    ;;
  twitter)
    WORKLOAD_DESC="--records=$COUNT_RECORDS --popularity=zipf:1.5 --keysize=pareto:40,15,0.05 --valuesize=pareto:100,50,0.7 --update=0" # --iadist=fb_ia
    ;;
  test)
    WORKLOAD_DESC="--records=$COUNT_RECORDS -K 100 -V 100 --update=0"
    ;;
  *)
    echo "invalid workload name"
    exit 1
esac

trap "handle_signal" SIGINT SIGHUP


function handle_signal {
	pkill mutilateudp
}

echo Loading ...
./mutilate -s $SERVER_HOST:$SERVER_PORT $WORKLOAD_DESC --loadonly -t 1
sleep 1

for i in $(seq $REPEAT); do
	echo Running agents ...
	./mutilateudp -A --threads $NUM_AGENTS &
	echo Running experiment $i ...
	TOTAL_CONN=$((CONN_PER_AGENT*NUM_AGENTS))
	./mutilateudp --time=$TIME $WORKLOAD_DESC \
		--server=$SERVER_HOST:$SERVER_UDP_PORT \
		--qps=0 \
		--noload --threads=1 --connections=$TOTAL_CONN \
		--measure_connections=1 --measure_qps=2000 \
		--agent=$AGENT &>> $LOG_FILE
	# Terminate
	handle_signal
	sleep 1
done

echo '=============================='
cat $LOG_FILE
