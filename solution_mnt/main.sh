#!/bin/bash

TARGET_BINARY=$1
SEED_INPUT_FILE=$2
ARG_LIST=$3
TARGET_WRITE_ADDRESS=$4
TARGET_WRITE_VALUE=$5
SOLUTION_INPUT_FILE=$6

# 1. run dynamoRIO
run_commands=$(python3 -c "print(' '.join('$ARG_LIST'.replace('TARGET_BINARY', '$TARGET_BINARY').replace('INPUT_FILE', '$SEED_INPUT_FILE').split(':')))")

/root/DynamoRIO/bin64/drrun \
  -root /root/DynamoRIO \
  -c /solution_mnt/dynamorio_tracers/build/libinstrace_simple.so -- $run_commands

python3 ./solver.py \
  $TARGET_BINARY \
  $SEED_INPUT_FILE \
  $ARG_LIST \
  $TARGET_WRITE_ADDRESS \
  $TARGET_WRITE_VALUE \
  $SOLUTION_INPUT_FILE
