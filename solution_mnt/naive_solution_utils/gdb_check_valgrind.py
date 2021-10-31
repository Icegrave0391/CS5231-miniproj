#!/usr/bin/python3
import sys
import subprocess
import os
import signal

os.setpgrp()

try:
    print("--- gdb_check_valgrind.py starts")

    TARGET_BINARY=sys.argv[1]
    RUN_ARGS=sys.argv[2:]
    print("--- TARGET_BINARY:", TARGET_BINARY)
    print("--- RUN_ARGS:", RUN_ARGS)

    valgrind_cmd = f"valgrind --leak-check=no --vgdb=yes --vgdb-error=0 {TARGET_BINARY} {' '.join(RUN_ARGS)} > /dev/null"
    print("--- valgrind_cmd:", valgrind_cmd)
    valgrind_process = subprocess.Popen(
        valgrind_cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        shell=True, 
        preexec_fn=os.setsid)

    from pygdbmi.gdbcontroller import GdbController
    gdb_command = None
    print("--- START GDB.")
    gdbmi = GdbController()  # Start gdb process

    valgrind_pid = None
    def valgrind_getline():
        global valgrind_pid
        line = valgrind_process.stderr.readline().decode()
        if len(line) == 0:
            return None
        if valgrind_pid is None: 
            if line.count("==") >= 2:
                valgrind_pid = line.strip().split("==")[1]
                print("--- Valgrind PID:", valgrind_pid)
        return line[:-1]

    def valgrind_getlines_until(stopcond=lambda x:True, map_func=lambda x:x):
        result_lines = []
        while True:
            line = valgrind_getline()
            result_lines.append(map_func(line))
            if stopcond(line): break
        return result_lines

    def check_print_resp(resp):
        for msg in resp:
            print(msg)
            if msg["message"] == "error":
                print("--- GDB ERROR", msg)
                raise Exception("GDB has error message" + str(msg)) 
            
    def interactive():
        while True:
            gdbcmd = input("Input GDB Command>").strip()
            if gdbcmd == "exit": break
            response = gdbmi.write(gdbcmd, timeout_sec=1,  raise_error_on_timeout=False)
            check_print_resp(response)

    # interactive()
    def cleanup():
        global gdbmi
        print("--- gdbmi exit")
        gdbmi.exit()
        print("--- kill valgrind process")
        valgrind_process.kill()
        if valgrind_pid is None:
            raise Exception("Valgrind_pid not found")
        kill_command = "kill -9 " + valgrind_pid
        print("--- kill command:", kill_command)
        try:
            os.system(kill_command)
        except:
            pass


    while True:
        line = valgrind_getline()
        if line is None: 
            print("--- ERROR: valgrind output unexpected")
            cleanup()
            raise Exception("Valgrind output found")

        if line.find("target remote |") >= 0:
            gdb_command = line[line.find("target remote |"):]
            print("--- FIND GDB COMMAND:", gdb_command)
            break
        else:
            print(line)

    response = gdbmi.write('file ' + TARGET_BINARY, timeout_sec=1,  raise_error_on_timeout=True)
    check_print_resp(response)
    response = gdbmi.write("set disable-randomization on",timeout_sec=0,  raise_error_on_timeout=False)
    check_print_resp(response)
    response = gdbmi.write("set confirm off",timeout_sec=0,  raise_error_on_timeout=False)
    check_print_resp(response)
    response = gdbmi.write("set pagination off",timeout_sec=0,  raise_error_on_timeout=False)
    check_print_resp(response)
    response = gdbmi.write(gdb_command, timeout_sec=2,  raise_error_on_timeout=True)
    check_print_resp(response)

    response = gdbmi.write("c", timeout_sec=10,  raise_error_on_timeout=True)
    check_print_resp(response)
    print("--- GDB commands sent.")

    remove_pid_prefix = lambda x : "==".join(x.split("==")[2:])
    report_str = None
    while True:
        line = valgrind_getline()
        if line is None: 
            print("--- Target exit normally.")
            cleanup()
            exit(0)
        if line.find("Use of uninitialised value")  >= 0 or line.find("Invalid write of size") >= 0:
            lines = valgrind_getlines_until(lambda x: remove_pid_prefix(x).strip() == "", remove_pid_prefix)
            report_lines = [remove_pid_prefix(line)] + lines
            report_str = "\n".join(report_lines)
            break
        else:
            print(line)

    print("--------------- report begin ---------------")
    print(report_str)
    print("--------------- report end ---------------")
    if not report_str.strip().startswith("Invalid write of size"):
        print("--- Not expected error type.")
        cleanup()
        exit(0)

    report_address = "0x" + report_str.split("Address 0x")[1].split(" is")[0]
    print("--- Error Address:", report_address)

    response = gdbmi.write(f"x/1bx {report_address}", timeout_sec=1,  raise_error_on_timeout=False)
    check_print_resp(response)
    response = gdbmi.write(f"si", timeout_sec=1,  raise_error_on_timeout=False)
    check_print_resp(response)
    addr_response = gdbmi.write(f"x/1bx {report_address}", timeout_sec=1,  raise_error_on_timeout=False)
    check_print_resp(addr_response)

    cleanup()

    for msg in reversed(addr_response):
        if msg["type"] == "console": 
            addr, addr_val = msg["payload"].replace("\\n", "").split(":\\t")
            print(f"OVERWRITE_ADDR={addr} OVERWRITE_VALUE={addr_val}")
    exit(0)
except Exception as e:
    print(e)
    os.killpg(0, signal.SIGKILL)

    