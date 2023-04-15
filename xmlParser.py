import xml.etree.ElementTree as ET
from datastructures import Vertex, Edge, Graph
import re

def get_md5(hashes):
    hashh = re.search('MD5=([0-9A-F]+)', hashes).group(0)[4:]
    return str(hashh)

def parse(path):
    graph = Graph([], [])

    file = open(path, 'r')
    lines = file.readlines()
    i = 1
    for line in lines:
        if i % 20 == 0:
            print(str(round((i / len(lines) * 100),2)) + " %")
        i = i + 1
        root = ET.ElementTree(ET.fromstring(line.replace(" xmlns='http://schemas.microsoft.com/win/2004/08/events/event'", '')))

        # Get event ID
        eid = int(root.find('System').find('EventID').text)

        # Parse all attributes
        attrs = {}
        for attr_element in root.find('EventData').findall('Data'):
            attrs[attr_element.attrib['Name']] = attr_element.text

        vertices = []
        edges = []

        if eid == 1:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ParentProcessGuid'],
                'Image': attrs['ParentImage']
            })
            to_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'spawn'))
        elif eid == 2:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('file', {
                'TargetFilename': attrs['TargetFilename']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'set-created'))
        elif eid == 3:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('ip', {
                'ip': attrs['DestinationIp']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'connect'))
        elif eid == 7:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('file', {
                'TargetFilename': attrs['ImageLoaded'],
                'HashMD5': get_md5(attrs['Hashes'])
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'load'))
        elif eid == 8:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['SourceProcessGuid'],
                'Image': attrs['SourceImage']
            })
            to_vtx = Vertex('process', {
                'ProcessGuid': attrs['TargetProcessGuid'],
                'Image': attrs['TargetImage']
            })
            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'remote-thread'))
        elif eid == 11:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('file', {
                'TargetFilename': attrs['TargetFilename']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'create'))
        elif eid == 12:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('key', {
                'TargetObject': attrs['TargetObject']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            if attrs['EventType'] == 'CreateKey':
                graph.add_edge(Edge(from_vtx, to_vtx, 'create-key'))
            else:
                graph.add_edge(Edge(from_vtx, to_vtx, 'delete-key'))
        elif eid == 13:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('key', {
                'TargetObject': attrs['TargetObject']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'set-key'))
        elif eid == 14:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('key', {
                'TargetObject': attrs['TargetObject']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'rename-key'))
        elif eid == 17:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('pipe', {
                'PipeName': attrs['PipeName']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'create-pipe'))
        elif eid == 18:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('pipe', {
                'PipeName': attrs['PipeName']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'connect-pipe'))
        elif eid == 22:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('domain', {
                'QueryName': attrs['QueryName']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'resolves'))
        elif eid == 26 or eid == 23:
            from_vtx = Vertex('process', {
                'ProcessGuid': attrs['ProcessGuid'],
                'Image': attrs['Image']
            })
            to_vtx = Vertex('file', {
                'TargetFilename': attrs['TargetFilename']
            })

            graph.add_vertex(from_vtx)
            graph.add_vertex(to_vtx)
            graph.add_edge(Edge(from_vtx, to_vtx, 'delete'))

    return graph
