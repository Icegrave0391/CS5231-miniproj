#!/usr/bin/python3

import sys
import subprocess

TARGET_BINARY = sys.argv[1]
SEED_INPUT_FILE = sys.argv[2]
ARG_LIST = sys.argv[3]
TARGET_WRITE_ADDRESS = sys.argv[4]
TARGET_WRITE_VALUE = sys.argv[5]
SOLUTION_INPUT_FILE = sys.argv[6]

print("--- Naive Solution ---")
print()
print("(Input) TARGET_BINARY:", TARGET_BINARY)
print("(Input) SEED_INPUT_FILE:", SEED_INPUT_FILE)
print("(Input) ARG_LIST:", ARG_LIST)
print("(Output) SOLUTION_INPUT_FILE:", SOLUTION_INPUT_FILE)
print()
print("(Config) TARGET_WRITE_ADDRESS:", TARGET_WRITE_ADDRESS)
print("(Config) TARGET_WRITE_VALUE:", TARGET_WRITE_VALUE)
print()

def gen_args(arg_list_template, target_binary, input_file):
    args = arg_list_template.replace("TARGET_BINARY", target_binary)\
        .replace("INPUT_FILE", input_file)\
        .split(":")
    return args

# read input as byte array
seed_input = None
with open(SEED_INPUT_FILE, "rb") as f:
    seed_input = f.read()

# use target value to replace each input byte
is_solution_found = False
solution_bytearray = None

for i in range(len(seed_input)): 
    print("mutate byte:", i)

    seed_input_copy = bytearray(seed_input)
    seed_input_copy[i] = int(TARGET_WRITE_VALUE, 16)

    with open(SOLUTION_INPUT_FILE, "wb") as fm:
        fm.write(seed_input_copy)

    # call checker
    args = gen_args(ARG_LIST, TARGET_BINARY, SOLUTION_INPUT_FILE)
    result = subprocess.check_output(
        ["./checkrun.sh"] + args, 
        cwd="./naive_solution_utils", 
        stderr=subprocess.STDOUT).decode('utf-8')
    print("run args:", ["./checkrun.sh"] + args)
    lastline = result.strip().splitlines()[-1].strip()
    result_dict = {}
    if lastline.startswith("OVERWRITE_ADDR="):
        print("last line of check result:", lastline)
        result_dict = {x[0]:x[1] for x in [y.split("=") for y in lastline.strip().split()]}
        if int(result_dict["OVERWRITE_ADDR"], 16) == int(TARGET_WRITE_ADDRESS, 16) \
        and int(result_dict["OVERWRITE_VALUE"], 16) == int(TARGET_WRITE_VALUE, 16):
            result_dict["PASS"] = True
        else:
            result_dict["PASS"] = False
    else:
        result_dict["PASS"] = False

    print("parsed check result:", result_dict)

    if result_dict["PASS"]:
        is_solution_found = True
        solution_bytearray = seed_input_copy
        break

if is_solution_found:
    print("Solution found! solution is at:", SOLUTION_INPUT_FILE)
    exit(0)

exit(44)

        

