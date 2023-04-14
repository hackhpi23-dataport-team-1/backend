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
    for line in lines:
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

    return graph
