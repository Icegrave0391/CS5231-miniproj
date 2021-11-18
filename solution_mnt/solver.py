import angr
import logging
import sys

from angr.exploration_techniques.tracer import TracerDesyncError
from collections import defaultdict
import claripy

from angr_solver.trace_parser import Parser
from angr_solver.plugin_manager import PluginManager
from angr_solver.procedure_manager import ProcedureManager
from angr_solver.taint_annos import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

TRACE_PATH = "/solution_mnt/angr_solver/tracefile1"
bin_path = "/testcases_mnt/PartA/manual1"
arg = "/testcases_mnt/PartA/manual1_seedinput"

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
    def __init__(self, taint_dict=defaultdict(lambda: -1)):
        super().__init__()
        self.taint_dict = taint_dict

    def get_region_taints(self, start, end):
        """ [start, end)"""
        taints = []
        for i in range(start, end):
            taints.append(self.taint_dict[i])
        return taints

    @angr.SimStatePlugin.memo
    def copy(self, _memo):
        return SimTaintEngine(self.taint_dict)

if __name__ == "__main__":

    parser = Parser(TRACE_PATH)
    # initialize 
    log.info(f"Initializing angr project...")
    project = angr.Project(bin_path, auto_load_libs=False)
    init_state = project.factory.entry_state(args=[bin_path, arg])
    # register plugin
    log.info(f"Registering siminput state plugin...")
    use_symbolic = False
    simcontent = _init_seedcontent(init_state, arg, use_symbolic=use_symbolic)
    
    init_state.register_plugin("seedfile", SimInputPlugin(arg, simcontent, use_symbolic=use_symbolic))
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

    while not simgr.complete():
        try:
            succ = simgr.active[0]
            log.debug(f"Stepping state {succ}")
            simgr.step()
        except TracerDesyncError:
            log.error(f"Trace file error occured. Check the parser.")   
            raise TracerDesyncError()

    log.info(f"Exploration finished.")
    import IPython; IPython.embed() 
