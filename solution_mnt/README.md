**Notice: Your solution and all the commands below should be run inside docker container. They are NOT meant to be run in VM directly.**

# Interface and loal test

- To test your solution, run `local_tester.sh` and select a testcase
```sh
./local_tester.sh
```

- To manually check the memory error caused by an input file, run `/testcases_mnt/eval_memcheck/checkrun.sh` 

```sh
/testcases_mnt/eval_memcheck/checkrun.sh <args..>

# example: check manual0 on manual0_seedinput
/testcases_mnt/eval_memcheck/checkrun.sh /testcases_mnt/PartA/manual0 /testcases_mnt/PartA/manual0_seedinput

# example: check rgb2ycbcr on exploit.tif
/testcases_mnt/eval_memcheck/checkrun.sh /testcases_mnt/PartB/real1/rgb2ycbcr /testcases_mnt/PartB/real1/exploit.tif /tmp/foo.tif
```

# Explanation of the naive solution

The naive solution has two parts: 
- A memory error checker in `naive_solution_utils` (copied from the `/testcases_mnt/eval_memcheck` directly) for checking a proposed input file; 
- A main program `naive_solution.py` that mutates the input and feed to the checker to see if it achieves the goal.

What is the naive solution doing?
```sh
# ----- loop over the steps below -----

# mutate seedinput by 1 byte and write to /tmp/manual0_solutioninput

# run valgrind on the target
<some environment variable setup...> valgrind --leak-check=no --vgdb=yes --vgdb-error=0 /testcases_mnt/PartA/manual0 /tmp/manual0_solutioninput

# run gdb
gdb /testcases_mnt/PartA/manual0

# connect to valgrind gdbserver
target remote | /usr/local/libexec/valgrind/../../bin/vgdb --pid=<valgrind gdbserver pid>

# trap on invalid memory write and get error address

# execute one instruction

# check error address again 
```

