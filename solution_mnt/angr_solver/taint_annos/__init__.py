from .seedrange import SeedRange
from .taint_annotation import TaintAnno
from typing import Optional


def extract_taints(symvar) -> list:
    taints = []
    for anno in symvar.annotations:
        if isinstance(anno, TaintAnno):
            taints.extend(anno.taint_offsets)
    return taints

def annotate_with_taint(symvar, taint_offsets:list):
    annos_to_remove = []
    for anno in symvar.annotations:
        if isinstance(anno, TaintAnno):
            annos_to_remove.append(anno)
    if annos_to_remove:
        symvar = symvar.remove_annotations(annos_to_remove)
    
    return symvar.annotate(TaintAnno(taint_offsets))
