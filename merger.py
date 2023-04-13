from datastructures import Vertex, Edge
from pprint import pprint

def merge_graphs(graph1, graph2):
    """ 
    Takes two graphs and merges the second graph into the first
    Adds missing vertices and edges to the graph.
    Updates existing vertices and edges with new attributes.
    """
    if graph2 is None:
        return graph1

    for vertex in graph2.vertices:
        if not vertex.id in [v.id for v in graph1.vertices]:
            graph1.add_vertex(vertex)
        else:
            for v in graph1.vertices:
                if v.id == vertex.id:
                    v.add_attribute(vertex.attr)
    
    for edge in graph2.edges:
        if not edge.id in [e.id for e in graph1.edges]:
            graph1.add_edge(edge)
        else:
            for e in graph1.edges:
                if e.id == edge.id:
                    e.add_attribute(edge.attr)
    
    return graph1



# vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
# vertex1 = Vertex(kind='ip', attr = {'ip': '17.253.144.10', 'domain':'apple.com'})
# graph = [vertex, vertex1]

# graph_update = merge_graphs(graph, enrich_ip(vertex))

# pprint(graph_update[2].__dict__)

