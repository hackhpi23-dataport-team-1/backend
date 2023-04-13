from datastructures import Vertex, Edge
from enrich import enrich_ip
from pprint import pprint

def merge_graphs(graph, subgraph):
    """ 
    Takes a list each containing vertices and a list of edges
    Creates a new Vertice (in the graph) if it doesn't exist yet
    Creates new edges if they don't exist yet
    Adds attributes to existing vertices
    """

    # get all ids in graph
    ids = [item.id for item in graph]

    for item in subgraph:
        if item.id not in ids:
            graph.append(item)
        else:
            [item.add_attribute(item.attr) for item_old in graph if item_old.id == item.id]
    return graph




# vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
# vertex1 = Vertex(kind='ip', attr = {'ip': '17.253.144.10', 'domain':'apple.com'})
# graph = [vertex, vertex1]

# graph_update = merge_graphs(graph, enrich_ip(vertex))

# pprint(graph_update[2].__dict__)

