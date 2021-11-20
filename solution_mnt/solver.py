import angr
import logging
import sys
import subprocess
import pathlib

from angr.exploration_techniques.tracer import TracerDesyncError
from collections import defaultdict
import claripy

from angr_solver.trace_parser import Parser
from angr_solver.plugin_manager import PluginManager
from angr_solver.procedure_manager import ProcedureManager
from angr_solver.taint_annos import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

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

TRACE_PATH = "/solution_mnt/angr_solver/tracefile3"
bin_path = "/testcases_mnt/PartA/manual3"
arg = "/testcases_mnt/PartA/manual3_seedinput"

def _init_seedcontent(state, fpath, use_symbolic: False):
    """
    We cannot use symbolic content and add constraint here, due to the large size (20256 in manual1) of input file.
    """
    try:
        f = open(fpath, "rb")
        content = f.read()
    except FileExistsError:
        log.error(f"Seedinput file {fpath} not exists.")
        return ""
    if not use_symbolic:
        return content

    length = len(content)
    sym_content = []
    for i in range(length):
        sym_content.append(state.solver.BVS("seed_%d" % i, 8, explicit_name=True))
    return claripy.Concat(*sym_content)


class SimInputPlugin(angr.SimStatePlugin):
    def __init__(self, fpath, seedcontent, use_symbolic=True, \
        seedcontent_addr=None, seedcontent_len=None):
        super().__init__()
        self.seedfile_path = fpath
        self.use_symbolic = use_symbolic
        self.seedcontent = _init_seedcontent(self.state, self.seedfile_path, use_symbolic) \
            if seedcontent is None else seedcontent
        self.seedcontent_addr = seedcontent_addr
        self.seedcontent_len = seedcontent_len

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SimInputPlugin(self.seedfile_path, self.seedcontent, \
            self.use_symbolic, self.seedcontent_addr, self.seedcontent_len)


class SimTaintEngine(angr.SimStatePlugin):
    """
    Taint engine, the taint_dict is used for byte-level address taint
    The value of taint_dict is the seed_offset to the seedinput_file
    """
    def __init__(self, taint_dict=defaultdict(lambda: -1), mark_offset=None):
        super().__init__()
        self.taint_dict = taint_dict
        self.mark_offset = mark_offset # mark the tainted seedinput offset

    def get_region_taints(self, start, end):
        """ [start, end)"""
        taints = []
        for i in range(start, end):
            taints.append(self.taint_dict[i])
        return taints

    @angr.SimStatePlugin.memo
    def copy(self, _memo):
        return SimTaintEngine(self.taint_dict, self.mark_offset)

if __name__ == "__main__":
    
    raw_args = gen_args(ARG_LIST, TARGET_BINARY, SEED_INPUT_FILE) # binary_name seedfile
    parser = Parser(TARGET_BINARY)
    log.critical("START")
    # initialize 
    log.info(f"Initializing angr project...")
    project = angr.Project(TARGET_BINARY, auto_load_libs=False)
    init_state = project.factory.entry_state(args=raw_args)
    # register plugin
    log.info(f"Registering siminput state plugin...")
    use_symbolic = False
    simcontent = _init_seedcontent(init_state, SEED_INPUT_FILE, use_symbolic=use_symbolic)
    init_state.register_plugin("seedfile", SimInputPlugin(SEED_INPUT_FILE, simcontent, use_symbolic=use_symbolic))
    init_state.register_plugin("taintengine", SimTaintEngine())

    simgr = project.factory.simgr(init_state)
    plgin_manager = PluginManager(project, simgr)
    proc_manager = ProcedureManager(project)

    tracer = angr.exploration_techniques.Tracer(
        trace=parser.bb_list,
        resiliency=True,
        copy_states=True,
        aslr=False,
    )
    simgr.use_technique(tracer)

    seedinput_offset = None

    while not simgr.complete():
        try:
            succ = simgr.active[0]
            # found the tainted seed offset, then break and mutate
            if succ.taintengine.mark_offset is not None:
                seedinput_offset = succ.taintengine.mark_offset
                break
            log.debug(f"Stepping state {succ}")
            simgr.step()
        except TracerDesyncError:
            log.error(f"Trace file error occured. Check the parser.")   
            raise TracerDesyncError()

    log.critical(f"Exploration finished.")
    # mutate
    simcontent_copy = bytearray(simcontent)
    if seedinput_offset < 0:
        log.error(f"Error with angr_solver.")
    else:
        simcontent_copy[seedinput_offset] = int(TARGET_WRITE_VALUE, 16)
        with open(SOLUTION_INPUT_FILE, "wb") as fm:
            fm.write(simcontent_copy)


