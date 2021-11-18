from typing import Set, Optional
from .seedrange import SeedRange
from claripy import Annotation


class TaintAnno(Annotation):    
    def __init__(self, taint_offsets:list):
        """
        Taint offsets is a byte-level map to the annotated value,
        the offset refer to its relevant seedfile offset, -1 means None.
        """
        super().__init__()
        self.taint_offsets = taint_offsets
    
    @property
    def relocatable(self):
        return True
    
    @property
    def eliminatable(self):
        return False
    
    # def relocate(self, src, dst):
    #     if dst.size() > src.size():


    def __hash__(self) -> int:
        return hash((tuple(self.taint_offsets), self.relocatable, self.eliminatable))
    
    def __eq__(self, o: object) -> bool:
        if not isinstance(o, TaintAnno):
            return False
        return self.taint_offsets == o.taint_offsets \
            and self.relocatable == o.relocatable \
            and self.eliminatable == o.eliminatable



