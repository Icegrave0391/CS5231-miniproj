class SeedRange:
    def __init__(self, offset: int, size: int=None):
        self.offset = offset
        self.size = size
    
    def __hash__(self):
        return hash((self.offset, self.size))
    
    def __eq__(self, other):
        if not isinstance(other, SeedRange):
            return False
        return self.offset == other.offset