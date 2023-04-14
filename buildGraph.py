from datastructures import *

class Graph:
    """
    generic graph model
    """
    def __init__(self, vertices = [], edges = []):
        self.vertices = vertices
        self.edges = edges

    def add_vertex(self, vertex:Vertex):
        self.vertices.append(vertex)
    
    def add_edge(self, edge:Edge):
        self.edges.append(edge)

    def connectVertex(self, startVertex:Vertex, endVertex:Vertex, kind, attr={}):
        # create edge
        edge = Edge(startVertex, endVertex,kind, attr)
        self.edges.append(edge)

        