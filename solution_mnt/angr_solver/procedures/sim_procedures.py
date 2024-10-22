import angr
import logging
from angr.state_plugins import heap, inspect

from cle.backends.externs.simdata.io_file import io_file_data_for_arch
from angr.storage.file import SimFileDescriptor
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)


def is_inline_proc(proc: angr.SimProcedure):
    """
    Determine whether the procedure is an inline call made by other procs
    """
    return not proc.use_state_arguments

def mode_to_flag(mode):
    # TODO improve this: handle mode = strings
    if mode[-1] == ord('b'): # lol who uses windows
        mode = mode[:-1]
    elif mode[-1] == ord('t'): # Rarely modes rt or wt are used, but identical to r and w
        mode = mode[:-1]
    mode = mode.replace(b'c', b'').replace(b'e', b'')
    all_modes = {
        b"r"  : angr.storage.file.Flags.O_RDONLY,
        b"r+" : angr.storage.file.Flags.O_RDWR,
        b"w"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT,
        b"w+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT,
        b"a"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND,
        b"a+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND
        }
    if mode not in all_modes:
        raise angr.SimProcedureError('unsupported file open mode %s' % mode)

    return all_modes[mode]


class Fopen(angr.SimProcedure):

    def run(self, p_addr, m_addr):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        p_strlen = self.inline_call(strlen, p_addr)
        m_strlen = self.inline_call(strlen, m_addr)

        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        m_expr = self.state.memory.load(m_addr, m_strlen.max_null_index, endness='Iend_BE')
        path = self.state.solver.eval(p_expr, cast_to=bytes)
        mode = self.state.solver.eval(m_expr, cast_to=bytes)

        flags = mode_to_flag(mode)
        # open simfile
        path_str = path.decode("utf-8")
        if path_str == self.state.seedfile.seedfile_path:
            log.info(f"fopen handling state seedinput file {path_str}...")
            simfile = angr.SimFile(path_str, content=self.state.seedfile.seedcontent)
            # create simfile
            self.state.fs.insert(path_str, simfile)
            flags = self.state.solver.eval(flags)
            # assign fd
            fd = self.state.posix._pick_fd()
            simfd = SimFileDescriptor(simfile, flags)
            simfd.set_state(self.state)
            self.state.posix.fd[fd] = simfd
            # return 
            malloc = angr.SIM_PROCEDURES['libc']['malloc']
            io_file_data = io_file_data_for_arch(self.state.arch)
            file_struct_ptr = self.inline_call(malloc, io_file_data['size']).ret_expr
            fd_bvv = self.state.solver.BVV(fd, 4 * 8) # int
            self.state.memory.store(file_struct_ptr + io_file_data['fd'],
                                    fd_bvv,
                                    endness=self.state.arch.memory_endness,
                                    inspect=False
                                    )
            return file_struct_ptr
        else:
            return angr.SIM_PROCEDURES["libc"]["fopen"](p_addr, m_addr)


class Fread(angr.SimProcedure):

    def run(self, dst, size, nm, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        ret = simfd.read(dst, size * nm)

        # record dst as state.seedinput.seedcontent_addr
        seed_dst_addr = self.state.solver.eval(dst)
        length = self.state.solver.eval(ret)
        self.state.seedfile.seedcontent_addr = self.state.solver.eval(dst)
        # initialize the TaintEngine of the state
        for off, addr in enumerate(range(seed_dst_addr, seed_dst_addr + length)):
            self.state.taintengine.taint_dict[addr] = off
        return self.state.solver.If(self.state.solver.Or(size == 0, nm == 0), 0, ret // size)


class Malloc(angr.SimProcedure):

    def run(self, sim_size):
        heap_ptr = self.state.heap._malloc(sim_size)
        size_int = self.state.solver.eval(sim_size)
        
        # add global
        # heap: Dict[ptr, Tuple(size, bool)] 
        # This bool indicates whether it has been freed (True for not freed)
        if not self.state.globals.get("heap"):
            self.state.globals["heap"] = {heap_ptr: (size_int, True)}
        else:
            self.state.globals["heap"][heap_ptr] = (size_int, True)

        return heap_ptr

class Free(angr.SimProcedure):

    def run(self, ptr):
        ptr_int = self.state.solver.eval(ptr)
        if ptr_int:
            try:
                # free relevant heap object
                size, vaild = self.state.globals["heap"][ptr_int]
                self.state.globals["heap"][ptr_int] = (size, False)
            except KeyError:
                pass
        self.state.heap._free(ptr)
    
class Strcpy(angr.SimProcedure):

    def run(self, dst, src):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        strncpy = angr.SIM_PROCEDURES['libc']['strncpy']
        src_len = self.inline_call(strlen, src)
        str_len_int = self.state.solver.eval(src_len.ret_expr)

        src_addr_int = self.state.solver.eval(src)
        dst_addr_int = self.state.solver.eval(dst)
        # memcpy
        src_content = self.state.memory.load(src_addr_int, str_len_int, inspect=True)
        self.state.memory.store(dst_addr_int, src_content, str_len_int, inspect=True)
        
        # check logic has moved to memcheck_plugin
        # for heap_addr, v in self.state.globals["heap"].items():
        #     heap_sz, valid = v[0], v[1]
        #     if dst_addr_int in range(heap_addr, heap_addr + heap_sz):
        #         # write to heap, check
                
        #         if (dst_addr_int + str_len_int - 1) <= heap_addr + heap_sz:
        #             break

        #         # invalid write
        #         log.critical(f"HEAP ERROR.\n    \
        #                 write content: {self.state.memory.load(src, str_len_int)}\n    \
        #                 insn address: {hex(self.state.addr)}\n   \
        #                 mem address: {hex(dst_addr_int)}")
        #         import IPython; IPython.embed()

        # ret_expr = self.inline_call(strncpy, dst, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr
        # import IPython; IPython.embed()
        return dst