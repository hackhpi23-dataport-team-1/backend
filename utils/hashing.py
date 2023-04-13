# Hashing function to translate a vertex kind + attributes into a consistent
# hash across different parts of the pipeline.
import hashlib

def hash_vid(kind, attrs) -> str:
    featuremap = {
        'ip': 'ip',
        'asn': 'asn',
        'domain': 'name'
    }

    data = attrs[featuremap[kind]]
    result = hashlib.md5(data.encode('utf-8'))
    return result.hexdigest()
