
from ipwhois import IPWhois
import socket
from datastructures import Vertex
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

        return result
    except:
        return RuntimeError("Error: IPWhois failed to lookup IP")



vertex = Vertex(kind='ip', attr = {'ip': '142.251.209.132', 'domain':'google.com'})
pprint(enrich_ip(vertex))
