import logging
from typing import List
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class Parser:

    def __init__(self, fpath="/solution_mnt/angr_solver/tracefile") -> None:
        self._bb_list: List[int] = []
        self.fpath = fpath
    
    @property
    def bb_list(self):
        if not self._bb_list:
            self._resolve()
        return self._bb_list

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