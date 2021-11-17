from os import stat
import angr
from .plugins import all_plugins
from angr import BP_BEFORE, BP_AFTER

class PluginManager:
    def __init__(self, project: angr.project, simgr: angr.SimulationManager):
        
        # 1. setup all available plugins
        self.plugins = [ 
            plugin(project, simgr)
            for plugin in all_plugins
        ]
        # 2. regist callback for breakpoints
        self.register_callbacks(simgr.active[0])

    def register_callbacks(self, state: angr.SimState):
        state.inspect.b("mem_read", when=BP_AFTER, action=self.mem_read)
        state.inspect.b("mem_write", when=BP_AFTER, action=self.mem_write)
        state.inspect.b("simprocedure", when=BP_AFTER, action=self.simprocedure)
        state.inspect.b("reg_read", when=BP_AFTER, action=self.reg_read)
        state.inspect.b("reg_write", when=BP_AFTER, action=self.reg_write)
        state.inspect.b("tmp_read", when=BP_AFTER, action=self.tmp_read)
        state.inspect.b("tmp_write", when=BP_AFTER, action=self.tmp_write)

    def stepped(self, simgr: angr.SimulationManager):
        for plgin in self.plugins:
            plgin.stepped(simgr)
    
    def mem_read(self, state: angr.SimState):
        for plgin in self.plugins:
            plgin.mem_read(state)
    
    def mem_write(self, state: angr.SimState):
        for plgin in self.plugins:
            plgin.mem_write(state)
    
    def simprocedure(self, state: angr.SimState):
        for plgin in self.plugins:
            plgin.simprocedure(state)
    
    def tmp_read(self, state: angr.SimState):
        for plgin in self.plugins:
            plgin.tmp_read(state)

    def tmp_write(self, state: angr.SimState):
        for plgin in self.plugins:
            plgin.tmp_write(state)

    def reg_read(self, state: angr.SimState):
        for plgin in self.plugins:
            plgin.reg_read(state)

    def reg_write(self, state: angr.SimState):
        for plgin in self.plugins:
            plgin.reg_write(state)