# Example of DynamoRIO tracers

The client code (all the `.c` and `.h` files under this folder) is obtained from https://github.com/DynamoRIO/dynamorio with BSD license.

Please be reminded of the original copyright. You are free to modify the code while obeying the license. You can declare the part written by you in `DECLARATION.md`.

This folder contains 3 example DynamoRIO client (tracers):
- `instrace_simple.c`
- `memtrace_simple.c`
- `memval_simple.c`

## Build

run `tracer_build.sh` to compile tracers under `./build`. 
See `CMakeLists.txt` for the detailed configuration of building a DynamoRIO client.

## RUN

You can use `tracer_run.sh` to run a binary using DynamoRIO with your customized tracers:
```
# run ls -la with the tracers above
./tracer_run.sh instrace_simple ls -la
./tracer_run.sh memtrace_simple ls -la
./tracer_run.sh memval_simple ls -la
```

After running the commands above, you should be able to see the trace files in `./build`.

## Run built-in Tracers of DynamoRIO

You can also try the built-in tracer of DynamoRIO, such as the memory tracer drcachesim.
```sh
# step 1: collect trace
/root/DynamoRIO/bin64/drrun \
  -root /root/DynamoRIO \
  -t drcachesim -offline -- $RUN_TARGET $TARGET_INPUTFILE

# step 2: decode trace
/root/DynamoRIO/bin64/drrun \
    -root /root/DynamoRIO \
    -t drcachesim -indir ./dir/to/saved/trace -simulator_type view 2>&1 | less
```