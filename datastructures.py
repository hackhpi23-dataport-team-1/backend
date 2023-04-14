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
class Graph:
    def __init__(self, vertices=[], edges=[]):
        self.vertices = vertices
        self.edges = edges
    
    def add_vertex(self, vertex:Vertex):
        if not vertex.id in [v.id for v in self.vertices]:
            self.vertices.append(vertex)
    
    def add_edge(self, edge:Edge):
        if not edge.id in [e.id for e in self.edges]:
            self.edges.append(edge)

    def to_dict(self):
        return {
            'vertices': [v.__dict__ for v in self.vertices],
            'edges': [e.__dict__ for e in self.edges]
        }

    def connectVertex(self, startVertex:Vertex, endVertex:Vertex, kind, attr={}):
        # create edge
        edge = Edge(startVertex, endVertex,kind, attr)
        self.edges.append(edge)

        