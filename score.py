from datastructures import Vertex, Graph
import random

def get_score(vertex: Vertex):
    # check if graph object is marked as malicious
    if 'malicious' in vertex.attr:
        if vertex.attr['malicious'] == True:
             return 100
        

    featuremap = {
        'ip': random.randint(20, 30),
        'asn': 20,
        'domain': 40,
        'has_asn': 40,
        "process": 50,
        "create" : 45,
        "file" : random.randint(10, 30),
        "dns" : 55,
        'create': 65,
        'key': random.randint(10, 30)
    }

    if vertex.kind in featuremap:
        return featuremap[vertex.kind]

    return 10


def update_score(graph: Graph):
    for vertex in graph.vertices:
        score = get_score(vertex)
        vertex.set_score(score)




# vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
# vertex1 = Vertex(kind='ip', attr = {'ip': '17.253.144.10', 'domain':'apple.com'})
# graph1 = enrich_ip(vertex)
# graph2 = enrich_ip(vertex1)

# merged1 = merge_graphs(graph1, graph2)

# update_score(merged1)

# pprint(merged1.to_dict())


