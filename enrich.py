
from ipwhois import IPWhois
import socket
from datastructures import Vertex
from pprint import pprint


def enrich_ip(vertex):
    ip = vertex.attr['ip']
    try:
        result = IPWhois(ip).lookup_whois(inc_raw=True)
        vertex.add_attribute(result)
        return result
    except:
        return RuntimeError("Error: IPWhois failed to lookup IP")


def enrich_asn(vertex):
    asn = vertex.attr['asn']
    pass

vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
pprint(enrich_ip(vertex))
