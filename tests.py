from datastructures import Vertex, Edge
from merger import merge_graphs
from pprint import pprint
from enrich import enrich_ip, check_blocklist


vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
vertex1 = Vertex(kind='ip', attr = {'ip': '17.253.144.10', 'domain':'apple.com'})
graph = [vertex, vertex1]

graph_update = merge_graphs(graph, enrich_ip(vertex))


assert graph_update[0].attr['asn'] == '15169'
assert graph_update[1].attr['ip'] == '17.253.144.10'
assert len(graph_update) == 4


mal_ip = 'http://makeupuccino.com/purveyance.php'
mal_ssl = '55e02c78e8a0f85fab9f05824647aba712e7b0b7'

assert check_blocklist(mal_ip) == True
assert check_blocklist(mal_ssl, ssl=True) == True
assert check_blocklist('oioioi', ssl=True) == False
assert check_blocklist('142.251.209.132') == False