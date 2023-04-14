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
        "file" : "TargetFilename",
        "dns" : "dns",
        'NetworkConnect': 'process',
        'key': 'TargetObject',

        'set-created': 'identity',
        'spawn': 'identity',
        'connect': 'identity',
        'load': 'identity',
        'remote-thread': 'identity',
        'create': 'identity',
        'create-key': 'identity',
        'delete-key': 'identity',
        'set-key': 'identity'
    }

    data = attrs[featuremap[kind]]
    result = hashlib.md5(str(data).encode('utf-8'))
    return result.hexdigest()
