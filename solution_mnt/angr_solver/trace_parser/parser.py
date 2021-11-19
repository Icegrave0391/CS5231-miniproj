import logging
from typing import List
from pathlib import Path

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class Parser:

    def __init__(self, bpath) -> None:
        self._bb_list: List[int] = []
        self.fpath = self._resolve_trace_path(bpath)
    
    @property
    def bb_list(self):
        if not self._bb_list:
            self._resolve()
        return self._bb_list

    def _resolve_trace_path(self, bpath: str):
        binary_path = Path(bpath)
        binary_name = binary_path.name
        trace_dir = Path("/solution_mnt/dynamorio_tracers/build")
        if not trace_dir.is_dir():
            raise FileNotFoundError("Please build DynamoRIO first.")
        
        for path in trace_dir.iterdir():
            fname = path.name
            if path.is_file() and fname.find(binary_name) >= 0 and fname.find("instrace") >= 0:
                return str(path)
        
        raise FileExistsError("Please run DynamoRIO instrace_simple first.")

    def _resolve(self):
        log.debug(f"Start resolving basic block list...")
        try:
            f = open(self.fpath, "r")
        except FileExistsError:
            log.error(f"File {self.fpath} not exists.")
            raise FileExistsError()
        
        insn_lines = f.readlines()[1:]
        bb_start_flg = True
        
        for insn_line in insn_lines:
            addr_str, op = insn_line.strip().split(",")
            insn_addr = int(addr_str, 16)

            # record basic block addr when it starts 
            if bb_start_flg:
                self._bb_list.append(insn_addr)
                bb_start_flg = False
            
            # mark the transition point as basic block end
            if op in ["call", "ret"] or op.startswith("j"):
                bb_start_flg = True
                continue
        
        f.close()
        log.debug(f"Finish resolving basic block list, len: \
            {len(self._bb_list)}")