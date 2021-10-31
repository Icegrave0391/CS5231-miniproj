#!/bin/bash
# use /bin/bash to intepret this file
echo "------- Local Test Script ------"
echo "A0: /testcases_mnt/PartA/manual0"
echo "A1: /testcases_mnt/PartA/manual1"
echo "A2: /testcases_mnt/PartA/manual2"
echo "A3: /testcases_mnt/PartA/manual3"
echo "B1: /testcases_mnt/PartB/real1/rgb2ycbcr"

read -p "Please input a testcase_id (A0/A1/A2/A3/B1):" testcase_id
ARG_LIST="TARGET_BINARY:INPUT_FILE"
if [ $testcase_id = "A0" ]; then
  TARGET_BINARY="/testcases_mnt/PartA/manual0"
  SEED_INPUT_FILE="/testcases_mnt/PartA/manual0_seedinput"
  CONFIG_FILE="/testcases_mnt/PartA/manual0_config"
  SOLUTION_INPUT_FILE="/tmp/manual0_solutioninput_12345678901"
elif [ $testcase_id = "A1" ]; then
  TARGET_BINARY="/testcases_mnt/PartA/manual1"
  SEED_INPUT_FILE="/testcases_mnt/PartA/manual1_seedinput"
  CONFIG_FILE="/testcases_mnt/PartA/manual1_config"
  SOLUTION_INPUT_FILE="/tmp/manual1_solutioninput_12345678901"
elif [ $testcase_id = "A2" ]; then
  TARGET_BINARY="/testcases_mnt/PartA/manual2"
  SEED_INPUT_FILE="/testcases_mnt/PartA/manual2_seedinput"
  CONFIG_FILE="/testcases_mnt/PartA/manual2_config"
  SOLUTION_INPUT_FILE="/tmp/manual2_solutioninput_12345678901"
elif [ $testcase_id = "A3" ]; then
  TARGET_BINARY="/testcases_mnt/PartA/manual3"
  SEED_INPUT_FILE="/testcases_mnt/PartA/manual3_seedinput"
  CONFIG_FILE="/testcases_mnt/PartA/manual3_config"
  SOLUTION_INPUT_FILE="/tmp/manual3_solutioninput_12345678901"
elif [ $testcase_id = "B1" ]; then
  TARGET_BINARY="/testcases_mnt/PartB/real1/rgb2ycbcr"
  SEED_INPUT_FILE="/testcases_mnt/PartB/real1/exploit.tif"
  ARG_LIST="TARGET_BINARY:INPUT_FILE:/tmp/foo.tif"
  CONFIG_FILE="/testcases_mnt/PartB/real1/config"
  SOLUTION_INPUT_FILE="/tmp/real1_solutioninput_1234567890123"
else
  echo "--- ERROR: unknown testcase_id: $testcase_id"
  exit
fi

# Read: TARGET_WRITE_ADDRESS TARGET_WRITE_VALUE
export $(grep -v '^#' $CONFIG_FILE | xargs -d '\n')

calling solution interface
chmod +x ./main.sh
./main.sh \
  $TARGET_BINARY \
  $SEED_INPUT_FILE \
  $ARG_LIST \
  $TARGET_WRITE_ADDRESS \
  $TARGET_WRITE_VALUE \
  $SOLUTION_INPUT_FILE

RETCODE=$?
if [ $RETCODE != 0 ]; then
echo "--- ERROR: failed with code "$RETCODE
exit
fi

echo "--- test solution file $SOLUTION_INPUT_FILE"
run_commands=$(python3 -c "print(' '.join('$ARG_LIST'.replace('TARGET_BINARY', '$TARGET_BINARY').replace('INPUT_FILE', '$SOLUTION_INPUT_FILE').split(':')))")
env CHECKER_PATH=/testcases_mnt/eval_memcheck \
  /testcases_mnt/eval_memcheck/checkrun.sh $run_commands \
  | python3 /testcases_mnt/eval_memcheck/check_match.py $TARGET_WRITE_ADDRESS $TARGET_WRITE_VALUE


