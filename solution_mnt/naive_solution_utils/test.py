import angr
from angr import BP_BEFORE, BP_AFTER

THRES = 0x7fffffffff00000

class Plgin:
    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        self.proj = proj
        self.simgr = simgr
    
    def stepped(self, simgr: angr.SimulationManager):
        pass
    
    def mem_read(self, state: angr.SimState):
        mem_read_addr = state.inspect.mem_read_address._model_concrete.value
        
        if mem_read_addr < THRES:
            print(f"mem read {state.inspect.mem_read_address}")
        # read_addr = state.inspect.mem_read_address
        # if mem_read_address == 0x4a123d8:
        #     print("MEMREAD!!!!")
        #     import IPython; IPython.embed()
    
    def mem_write(self, state: angr.SimState):
        mem_write_addr = state.inspect.mem_write_address._model_concrete.value

        print(f"mem write {state.inspect.mem_write_address}")
        # read_addr = state.inspect.mem_read_address
        # if mem_write_address == 0x4a123d8:
        #     print("MEMWRITE!!!!")
        #     import IPython; IPython.embed()

class Pluginmanager:
    def __init__(self, project: angr.project, simgr: angr.SimulationManager):
        self.plgin = Plgin(project, simgr)
        self.register_callbacks(simgr.active[0])
        
    def register_callbacks(self, state: angr.SimState):
        state.inspect.b("mem_read", when=BP_AFTER, action=self.mem_read)
        state.inspect.b("mem_write", when=BP_AFTER, action=self.mem_write)
    
    def mem_read(self, state: angr.SimState):
        self.plgin.mem_read(state)
    
    def mem_write(self, state: angr.SimState):
        self.plgin.mem_write(state)
                
                
bin_path = "/testcases_mnt/PartA/manual0"

print("start prepare")

project = angr.Project(bin_path)
init_state = project.factory.blank_state()

simgr = project.factory.simgr(init_state)
plgin_manager = Pluginmanager(project, simgr)

while not simgr.complete():
    simgr.step()
    

