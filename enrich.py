
from ipwhois import IPWhois
import socket
from datastructures import Vertex, Edge
from pprint import pprint


def enrich_ip(vertex):
    ip = vertex.attr['ip']
    try:
        # get IP info
        result = IPWhois(ip).lookup_whois(inc_raw=True)

        # extract info and update vertex
        attr = {
            'asn': result['asn'],
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
        edge = Edge(source=vertex.id, target=asn_vertex.id, kind='has_asn')

        return vertex, asn_vertex, edge
    except:
        return RuntimeError("Error: IPWhois failed to lookup IP")


def check_blacklist(input):
    with open('data/blacklist.txt', 'r') as f:
        if input in f.readlines():
            return True
        return False

# vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
# vertex, asn_vertex, edge = enrich_ip(vertex)
# pprint(enrich_ip(vertex))
# print(asn_vertex.__dict__)
