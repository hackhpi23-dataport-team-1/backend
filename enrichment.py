
from ipwhois import IPWhois


class Enrichments:
        def __init__(self, ip):
            self.ip = ip
    
        def get_whois(self):
            try:
                result = IPWhois(self.ip).lookup_whois(inc_raw=True)
                return result
            except:
                 return RuntimeError("Error: IPWhois failed to lookup IP")
    
        def get_ip(self):
            return self.ip
    