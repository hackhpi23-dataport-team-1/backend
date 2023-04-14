from utils.hashing import hash_vid
    

class Vertex:
    """
    vertex type

    kind: 
    "ip",
    "process",
    "file"
    """
    def __init__(self, kind, attr={}):
        self.id = hash_vid(kind, {kind:attr})
        self.kind = kind
        self.score = None
        self.attr = attr

    def add_attribute(self, dict):
        self.attr.update(dict)

    def set_score(self, score):
        self.score = score


class Edge:
    """
    edge 

    kind:
    "create"

    "tcp", "udp"  between two ip nodes
    """
    def __init__(self, source:Vertex,  target:Vertex, kind, attr={}):
        self.source = source
        self.target = target
        self.kind = kind
        self.attr = attr
        self.id = hash_vid(kind, {kind:attr})

    def add_attribute(self, dict):
        self.attr.update(dict)
