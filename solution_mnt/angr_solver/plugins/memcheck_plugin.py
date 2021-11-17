import angr
import logging
import inspect

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
        expr = state.inspect.mem_read_expr
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

        heap_regions = state.globals["heap"].items()
        for heap_ptr, val in heap_regions:
            size, vaild = val
            heap_overflow_loc = heap_ptr + size
            if write_addr_int == heap_overflow_loc or \
                (write_addr_int in range(heap_ptr, heap_ptr + size) and not vaild) or\
                write_addr_int in range(heap_ptr - 8, heap_ptr):

                write_content = state.inspect.mem_write_expr
                log.critical(f"HEAP ERROR.\n    \
                        write content: {write_content}\n    \
                        insn address: {hex(state.addr)}\n   \
                        mem address: {hex(write_addr_int)}")




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
        