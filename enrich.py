
from ipwhois import IPWhois
from dotenv import load_dotenv
from datastructures import Vertex, Edge, Graph
import hashlib
import requests
import os
from merger import merge_graphs
from pprint import pprint
load_dotenv()

def enrich(graph: Graph):
    ip_vertices = [v for v in graph.vertices if v.kind == 'ip']
    file_vertices = [v for v in graph.vertices if v.kind == 'file']

    for vertex in ip_vertices:
        enriched = enrich_ip(vertex)
        merge_graphs(graph, enriched)

    # enrich file vertices
    for vertex in file_vertices:
        enriched = enrich_file(vertex)
        merge_graphs(graph, enriched)

    return graph

    

def enrich_ip(vertex: Vertex):
    ip = vertex.attr['ip']
    try:
        # get IP info
        result = IPWhois(ip).lookup_whois(inc_raw=True)

        # extract info and update vertex
        attr = {
            'asn': result['asn'],
            'malicious': check_blocklist(ip),
        }
        vertex.add_attribute(attr)
        vertex.add_attribute(result['nets'][0])

        # create new vertex for ASN
        asn_attrs = {
            'asn': result['asn'],
            'asn_cidr': result['asn_cidr'],
            'asn_country_code': result['asn_country_code'],
            'asn_date': result['asn_date'],
            'asn_description': result['asn_description'],
            'asn_registry': result['asn_registry'],
            'range': result['nets'][0]['range'],
        }
        asn_vertex = Vertex(kind='asn', attr = asn_attrs)

        # create edge between IP and ASN
        edge = Edge(source=vertex.id, target=asn_vertex.id, kind='has_asn', attr={'asn': result['asn']})

        return Graph([vertex, asn_vertex], [edge])
    except:
        return None


def check_blocklist(input, ssl=False):
    """ Takes a domain or IP address and check if it is blacklisted"""
    try:
        if ssl:
            if input in open('blocklist/ssl_blacklist.txt').read():
                return True
        else:
            if input in open('blocklist/ip_blacklist.txt').read():
                return True
        return False
    
    except: 
        print('Error: Could not open blacklist.txt')
        return None



def enrich_file(vertex: Vertex):
    """
    makes a request to the VirusTotal API to get file info and adds
    VT_API_KEY as x-apikey to the header
    """
    file = vertex.attr['file']
    # hash file with MD5
    hash = hashlib.md5(file.encode('utf-8')).hexdigest()

    # make request to VirusTotal API
    url = 'https://www.virustotal.com/api/v3/files/{hash}'.format(hash=hash)
    headers = {
        'x-apikey': os.getenv('VT_API_KEY')
    }
    response = requests.get(url, headers=headers)

    # extract info and update vertex
    response_json = response.json()
    result = response_json['data']['attributes']['last_analysis_results']
    attrs = {'malicious': False }
    # check if in any result dict is a 'result' not none
    for key, value in result.items():
        if value['result'] != None:
            attrs = {
                'malicious': True,
                'malware_detect': key,
                'malware_result': value
            }
    vertex.update(attrs)
    return vertex



# vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
# vertex1 = Vertex(kind='ip', attr = {'ip': '17.253.144.10', 'domain':'apple.com'})
# graph1 = enrich_ip(vertex)
# graph2 = enrich_ip(vertex)
# # pprint(enrich_ip(vertex))
# # pprint(graph.to_dict())

# merged = merge_graphs(graph1, graph2)


# pprint(merged.to_dict())