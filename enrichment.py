
from ipwhois import IPWhois
import socket


class Enrichments:
        def get_whois(self, ip, domain=False):
            if(domain == True):
                ip = socket.gethostbyname('www.google.com')

            try:
                result = IPWhois(ip).lookup_whois(inc_raw=True)
                return result
            except:
                return RuntimeError("Error: IPWhois failed to lookup IP")
