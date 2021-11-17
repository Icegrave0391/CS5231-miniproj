import angr

class PluginBase:
    """
    Base class for attached analysis plugins.
    """
    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        self.proj = proj
        self.simgr = simgr
    
    def stepped(self, simgr: angr.SimulationManager):
        pass

    def complete(self, simgr: angr.SimulationManager):
        pass

    def mem_read(self, state: angr.SimState):
        pass

    def mem_write(self, state: angr.SimState):
        pass
    
    def reg_read(self, state: angr.SimState):
        pass

    def reg_write(self, state: angr.SimState):
        pass

    def tmp_read(self, state: angr.SimState):
        pass

    def tmp_write(self, state: angr.SimState):
        pass

    def simprocedure(self, state: angr.SimState):
        pass