# Hashing function to translate a vertex kind + attributes into a consistent
# hash across different parts of the pipeline.
import hashlib

def hash_vid(kind, attrs) -> str:
    featuremap = {
        'ip': 'ip',
        'asn': 'asn',
        'domain': 'name',
        'has_asn': 'asn',
        "process": "ProcessGuid",
        "Dummy" : "Dummy",
        "create" : "create",
        "file" : "TargetFilename",
        "dns" : "dns",
        'NetworkConnect': 'process',
        'create': 'level',

        'set-created': 'identity'
    }

    data = attrs[featuremap[kind]]
    result = hashlib.md5(str(data).encode('utf-8'))
    return result.hexdigest()
