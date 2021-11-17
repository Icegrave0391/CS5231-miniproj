import angr
import logging
import subprocess
import sys

from angr.exploration_techniques.tracer import TracerDesyncError
import claripy

from angr_solver.trace_parser import Parser
from angr_solver.plugin_manager import PluginManager
from angr_solver.procedure_manager import ProcedureManager

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

TRACE_PATH = "/solution_mnt/angr_solver/tracefile"
bin_path = "/testcases_mnt/PartA/manual0"
arg = "/testcases_mnt/PartA/manual0_seedinput"

TARGET_BINARY = sys.argv[1]
SEED_INPUT_FILE = sys.argv[2]
ARG_LIST = sys.argv[3]
TARGET_WRITE_ADDRESS = sys.argv[4]
TARGET_WRITE_VALUE = sys.argv[5]
SOLUTION_INPUT_FILE = sys.argv[6]

def gen_args(arg_list_template, target_binary, input_file):
    args = arg_list_template.replace("TARGET_BINARY", target_binary)\
        .replace("INPUT_FILE", input_file)\
        .split(":")
    return args

def _init_seedcontent(state, fpath, use_symbolic: False):
        try:
            f = open(fpath, "r")
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
    def __init__(self, fpath, seedcontent, use_symbolic=True):
        super().__init__()
        self.seedfile_path = fpath
        self.use_symbolic = use_symbolic
        self.seedcontent = _init_seedcontent(self.state, self.seedfile_path, use_symbolic) \
            if seedcontent is None else seedcontent
        
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SimInputPlugin(self.seedfile_path, self.seedcontent, self.use_symbolic)
        

if __name__ == "__main__":

    parser = Parser(TRACE_PATH)
    # initialize 
    log.info(f"Initializing angr project...")
    project = angr.Project(bin_path, auto_load_libs=False)
    init_state = project.factory.entry_state(args=[bin_path, arg])
    # register plugin
    log.info(f"Registering siminput state plugin...")
    simcontent = _init_seedcontent(init_state, arg, use_symbolic=True)
    init_state.register_plugin("seedfile", SimInputPlugin(arg, simcontent, use_symbolic=True))
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

    while not simgr.complete():
        try:
            succ = simgr.active[0]
            log.debug(f"Stepping state {succ}")
            simgr.step()
        except TracerDesyncError:
            log.error(f"Trace file error occured. Check the parser.")   
            raise TracerDesyncError()

    log.info(f"Exploration finished.")
    

    # call checker
    args = gen_args(ARG_LIST, TARGET_BINARY, SOLUTION_INPUT_FILE)
    result = subprocess.check_output(
        ["./checkrun.sh"] + args, 
        cwd="./naive_solution_utils", 
        stderr=subprocess.STDOUT).decode('utf-8')
    print("run args:", ["./checkrun.sh"] + args)
    lastline = result.strip().splitlines()[-1].strip()
    result_dict = {}
    import IPython; IPython.embed()
