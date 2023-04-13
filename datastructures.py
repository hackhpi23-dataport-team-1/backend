
class Edge:
    def __init__(self, source,  target, kind, attr={}):
        self.source = source
        self.target = target
        self.kind = kind
        self.attr = attr

    def add_attribute(self, dict):
        self.attr.update(dict)
    
class Vertex:
    def __init__(self, kind, attr={}):
        self.kind = kind
        self.score = None
        self.attr = attr

    def add_attribute(self, dict):
        self.attr.update(dict)

    def set_score(self, score):
        self.score = score

