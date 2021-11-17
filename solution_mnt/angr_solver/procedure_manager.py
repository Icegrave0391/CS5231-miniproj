import angr
from .procedures import all_hooks

def is_inline_proc(proc: angr.SimProcedure):
    """
    Determine whether the procedure is an inline call made by other procs
    """
    return not proc.use_state_arguments

class ProcedureManager:
    
    def __init__(self, project: angr.Project) -> None:
        self._proj = project
        self._hook()

    def _hook(self):
        for symbol, proc in all_hooks.items():
            self._proj.hook_symbol(symbol, proc())
    