#!/bin/bash
# Check when running a command,
#   1. whether it will hit memory write error on some address;
#   2. what is the value write to that address

# some examples of run this script:
# CHECKER_PATH=$PWD ./checkrun.sh /testcases_mnt/PartA/manual0 /testcases_mnt/PartA/manual0_seedinput
# CHECKER_PATH=$PWD ./checkrun.sh /testcases_mnt/PartB/real1/rgb2ycbcr /testcases_mnt/PartB/real1/exploit.tif /tmp/foo.tif

if [ -z $CHECKER_PATH ]; then 
CHECKER_PATH="/solution_mnt/naive_solution_utils"
fi

env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root USER=root \
    python3 $CHECKER_PATH/gdb_check_valgrind.py "$@"


