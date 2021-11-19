#!/bin/bash
set -e
CLIENT=$1
# the rest of the arguments are passed through

echo "${@:2}"

/root/DynamoRIO/bin64/drrun \
  -root /root/DynamoRIO \
  -c /solution_mnt/dynamorio_tracers/build/lib$CLIENT.so -- "${@:2}"

