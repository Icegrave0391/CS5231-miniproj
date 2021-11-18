import angr
import logging
import inspect

from ..taint_annos import *
from angr.errors import SimValueError
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

from ..procedure_manager import is_inline_proc
from .plugin_base import PluginBase

address_thres = 0x7ffffff0

class MemcheckPlugin(PluginBase):

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug(f"Memcheck Plugin Initialized.")

    def mem_read_before(self, state: angr.SimState):
        """
        Annotate seedfile region as taint 
        """
        # ensure the seedcontent has occurred
        if state.seedfile.seedcontent_addr is None:
            return

        read_addr_bv = state.inspect.mem_read_address
        read_addr_int = state.solver.eval(read_addr_bv)
        read_len = state.solver.eval(state.inspect.mem_read_length)

        update_taint = False

        # get taints from taint engine
        taints = []
        for addr in range(read_addr_int, read_addr_int + read_len):
            taints.append(state.taintengine.taint_dict[addr])
        
        # annotate the value and write back to memory
        update_taint = not all(taint == -1 for taint in taints)
        if update_taint:
            mem_content = state.memory.load(read_addr_int, read_len, inspect=False)
            log.debug(f"Before_read addr {hex(read_addr_int)}, size: {read_len}, content: {mem_content}\n   \
                taints: {taints}")

            mem_content = annotate_with_taint(mem_content, taints)
            state.memory.store(read_addr_int, mem_content, read_len, inspect=False)


    def mem_read(self, state: angr.SimState):
        read_addr_bv = state.inspect.mem_read_address
        expr = state.inspect.mem_read_expr
        try:
            read_addr_int = state.solver.eval_one(read_addr_bv)
        except SimValueError:
            read_addr_int = 0
            log.error(f"Unsat read address {read_addr_bv}.")
        if read_addr_int and read_addr_int < address_thres:
            log.info(f"Addr {hex(state.addr)}, readmem: {hex(read_addr_int)}")
    
    def mem_write(self, state: angr.SimState):
        write_addr_bv = state.inspect.mem_write_address
        try:
            write_addr_int = state.solver.eval_one(write_addr_bv)
        except SimValueError:
            write_addr_int = 0
            log.error(f"Unsat write address {write_addr_bv}.")
        if write_addr_int and write_addr_int < address_thres:
            log.info(f"Addr {hex(state.addr)}, writemem: {hex(write_addr_int)}")
        
        # heaps
        if "heap" not in state.globals.keys():
            return

        # update taint to memory
        write_addr_content = state.inspect.mem_write_expr
        write_addr_length = write_addr_content.size() // 8
        taints = extract_taints(write_addr_content)

        if not all(taint == -1 for taint in taints):
            if len(taints) != write_addr_length:  
                pass
            else:
                for i, addr in enumerate(range(write_addr_int, write_addr_int + write_addr_length)):
                    state.taintengine.taint_dict[addr] = taints[i]

        heap_regions = state.globals["heap"].items()
        for heap_ptr, val in heap_regions:
            size, vaild = val
            heap_overflow_loc = heap_ptr + size

            if self._loc_in_heap_range(state, heap_overflow_loc):
                continue

            if write_addr_int == heap_overflow_loc or \
                (write_addr_int in range(heap_ptr, heap_ptr + size) and not vaild) or\
                write_addr_int in range(heap_ptr - 8, heap_ptr):

                write_content = state.inspect.mem_write_expr
                log.critical(f"HEAP ERROR.\n    \
                        write content: {write_content}\n    \
                        insn address: {hex(state.addr)}\n   \
                        mem address: {hex(write_addr_int)}")

                import IPython; IPython.embed()

    def _loc_in_heap_range(self, state, loc: int):
            heaps = state.globals["heap"].items()
            for heap_addr, v in heaps:
                if loc in range(heap_addr, heap_addr + v[0]):
                    return True
            return False


    def simprocedure(self, state: angr.SimState):
        proc = state.inspect.simprocedure
        if proc is None:
            log.info(f"Reached a syscall SimProcedure.")
            return
        log.info(f"Reached Simprocedure {proc}")
        arg_spec = inspect.getfullargspec(proc.run)
        for i in range(proc.num_args):
            arg = proc.arg(i)
            try:
                arg_name = arg_spec[0][i + 1]
            except IndexError:
                arg_name = str(i)
            log.info(f" {arg_name}: {arg}")
        
        result = state.inspect.simprocedure_result
        if isinstance(result, int):
            result = hex(result)
        log.info(f" Returned: {result}")

        # add checker for malloc
        