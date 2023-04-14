import xml.etree.ElementTree as ET
# from lxml import etree
from io import StringIO
import sys,os
import csv

from buildGraph import *

os.chdir(os.path.dirname(os.path.abspath(__file__)))

EVENT_PARSE = 1
EVENTDATA_PARSE = 2

encodingRule = "utf-16-le"

typeArr = {"event": EVENT_PARSE, "EventData" : EVENTDATA_PARSE}
# typeArr = {"Event": EVENT_PARSE, "EventData" : EVENTDATA_PARSE}

def newObject(tag):
    """
    given the tag, to decide whether it is a nested element or a new object
    """
    if tag in typeArr:
        return typeArr[tag]
    else:
        return None
    
# replacement strings
WINDOWS_LINE_ENDING = b'\r\n'
UNIX_LINE_ENDING = b'\n'

def convertWinToUnix(filepath):
    """
    convert CRLF to LF
    """
    with open(filepath, 'rb') as open_file:
        content = open_file.read()
        
    # Windows ➡ Unix
    content = content.replace(WINDOWS_LINE_ENDING, UNIX_LINE_ENDING)
    with open(filepath, 'wb') as open_file:
        open_file.write(content)

def addRoot(filepath):
    """
    add root element for xml file
    """
    addRoot = True
    convertWinToUnix(filepath)
    # with open(filepath, encoding="utf8", errors='ignore') as f:
    with open(filepath, encoding=encodingRule) as f:
        first_line = f.readline()
        if "<Root>" in first_line :
            addRoot = False
        else:
            second_line = f.readline()
            if "<Root>" in second_line:
                addRoot = False
        # add </Root>
    if addRoot:
        with open(filepath, "a",encoding=encodingRule) as f:
            f.write("</Root>")
        # add <Root>
        with open(filepath,"r+", encoding=encodingRule) as f:
            content = f.read()
            f.seek(0,0)
            f.write("<Root>" + "\n" + content)
    
def parseElem(filepath):
    """
    given the filepath of a xml file,
    remove all the namespace,
    return an array, with each element a dictionary, storing a type 
    -----
    Parameters:
    ------
    filepath: str
    path to the xml file

    return:

    array of type elements example:

    {'type': 'Event', 'System': '\n      ', 'Provider': None, 'EventID': '13', 'Version': '2', 'Level': '4', 'Task': '13', 'Opcode': '0', 'Keywords': '0x8000000000000000', 'TimeCreated': None, 'EventRecordID': '1722721', 'Correlation': None, 'Execution': None, 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'Computer': 'DESKTOP-FPVDM4B', 'Security': None}, {'type': 'EventData', 'RuleName': '-', 'EventType': 'SetValue', 'UtcTime': '2021-09-30 14:34:09.448', 'ProcessGuid': '{de1f7a01-cad9-6155-5200-000000000600}', 'ProcessId': '2292', 'Image': 'C:\\Windows\\system32\\svchost.exe', 'TargetObject': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\Activation\\Data\\93\\HostId', 'Details': 'Binary Data'},


    """ 
    addRoot(filepath)
    it = ET.iterparse(filepath,events=("start",))
    # it = ET.iterparse(filepath,events=("start","end"))
    # it = ET.parse(filepath)
    # it = it.getroot()
    # it = iter(it)
    newElem = False
    parseElemArrs = []
    parseElem = None
    currentType = None
    for temp_, el in it:
        prefix, has_namespace, postfix = el.tag.partition('}')
        if has_namespace:
            el.tag = postfix  # strip all namespaces
        # check if a new object
        parseType = newObject(el.tag)
        if (parseType is not None): 
            # new element
            newElem = True
            currentType = parseType
            if parseElem is not None:
                parseElemArrs.append(parseElem)
            parseElem = dict()
            # event type event parser
            parseElem["type"] = el.tag
        elif parseElem is not None:
            # already parseElem created
            if currentType == EVENT_PARSE:
                parseElem[el.tag] = el.text
            elif currentType == EVENTDATA_PARSE:
                parseElem[el.attrib["Name"]] = el.text

        for at in list(el.attrib.keys()): # strip namespaces of attributes too
            if '}' in at:
                newat = at.split('}', 1)[1]
                el.attrib[newat] = el.attrib[at]
                del el.attrib[at]

    if parseElem is not None:
        # append the last one
        parseElemArrs.append(parseElem)
    return parseElemArrs
    # return it.root

def parseEvent(parseElemArrs):
    """
    given the array of parsed elements from xml, extract information for graph building
    """
    for elemDict in parseElemArrs:
        if elemDict["type"] == "Event":
            # new event
            eventType = elemDict["EventID"]

        if elemDict["type"] == "EventData":
            if eventType == '1':
                pass
            elif eventType == "11":
                # create process 
                pass


def parseElem2(filepath):
    """
    given the array of parsed elements from xml, extract information for graph building
    """
    # addRoot(filepath)
    it = ET.iterparse(filepath,events=("start",))
    # it = ET.iterparse(filepath,events=("start","end"))
    # it = ET.parse(filepath)
    # it = it.getroot()
    # it = iter(it)
    newElem = False
    parseElemArrs = []
    parseElem = None
    currentType = None
    for temp_, el in it:
        prefix, has_namespace, postfix = el.tag.partition('}')
        if has_namespace:
            el.tag = postfix  # strip all namespaces
        # check if a new object
        parseType = newObject(el.tag)
        if (parseType is not None): 
            # new element
            newElem = True
            currentType = parseType
            if parseElem is not None:
                parseElemArrs.append(parseElem)
            parseElem = dict()
            # event type event parser
            parseElem["attrib"] = el.attrib
        elif parseElem is not None:
            # already parseElem created
            # should be data
            parseElem[el.attrib["name"]] = el.text
            # if currentType == EVENT_PARSE:
            #     parseElem[el.tag] = el.text
            # elif currentType == EVENTDATA_PARSE:
            #     parseElem[el.attrib["Name"]] = el.text

        for at in list(el.attrib.keys()): # strip namespaces of attributes too
            if '}' in at:
                newat = at.split('}', 1)[1]
                el.attrib[newat] = el.attrib[at]
                del el.attrib[at]

    if parseElem is not None:
        # append the last one
        parseElemArrs.append(parseElem)
    return parseElemArrs

def parseEvent2(parseElemArrs):
    """
    given the array of parsed elements from xml, extract information for graph building
    """
    vertices = []
    edges = []
    for elemDict in parseElemArrs:
        # get name
        eventName = elemDict["attrib"]["name"]
        eventID = elemDict["attrib"]["value"]
        # get process ID
        processGUID = elemDict["ProcessGuid"]
        processID = elemDict["ProcessId"]
        processNode = Vertex("process", elemDict)
        vertices.append(processNode)
        if eventID == "1":
            pass
        elif eventID == "3":
            # network connection
            SrcEntityAttr = {"SourceIp": elemDict["SourceIp"],"SourceHostname": elemDict["SourceHostname"],"SourcePort": elemDict["SourcePort"], "SourcePortName" : elemDict["SourcePortName"]}
            DestEntityAttr = {"DestinationIp": elemDict["DestinationIp"],"DestinationHostname": elemDict["DestinationHostname"],"DestinationPort": elemDict["DestinationPort"], "DestinationPortName" : elemDict["DestinationPortName"]}
            # create two vertices
            srcNode = Vertex("ip",SrcEntityAttr)
            destNode = Vertex("ip", DestEntityAttr)
            vertices.append(srcNode)
            vertices.append(destNode)
            # create edges
            protocolName = elemDict["Protocol"]
            protocolEdge = Edge(srcNode, destNode, protocolName, {**SrcEntityAttr, **DestEntityAttr})
            edges.append(protocolEdge)
            # connect process to the internet ids
            processSrcEdge = Edge(processNode, srcNode, "create", elemDict)
            processDestEdge = Edge(processNode, destNode, "create", elemDict)
            edges.append(processSrcEdge)
            edges.append(processDestEdge)

        elif eventID == "11":
            # file create
            # create a new vertex file
            fileAttr = {"filename" : elemDict["TargetFilename"], "CreationUtcTime" : elemDict["CreationUtcTime"], "Hash" : elemDict["Hash"], "Contents": elemDict["Contents"], "User": elemDict["User"]}

            fileNode = Vertex("file",fileAttr)
            vertices.append(fileNode)
            # connect edge
            createEdge = Edge(processNode, fileNode, "create", fileAttr)
            edges.append(createEdge)
        elif eventID == "22":
            # DNS event
            dnsAttr = {"QueryName" : elemDict["QueryName"], "QueryStatus" : elemDict["QueryStatus"], "QueryResults": elemDict["QueryResults"], "Image" : elemDict["Image"], "User" : elemDict["User"]}
            
            dnsNode = Vertex("dns", dnsAttr)
            vertices.append(fileNode)
            createEdge = Edge(processNode, dnsNode, "create", dnsAttr)
            edges.append(createEdge)
    g = Graph(vertices, edges)
    return g
if __name__ == "__main__":
    # temp_parseElemArr = parseElem("../exampleData/twoEvents.xml")
    # temp_parseElemArr = parseElem("../exampleData/twoEvents_orig.xml")
    # temp_parseElemArr = parseElem("exampleData/temp.xml")
    temp_parseElemArr = parseElem2("exampleData/newEvent.xml")
    g = parseEvent2(temp_parseElemArr)
    # temp_parseElemArr = parseElem2("exampleData/schema.xml")

    print(temp_parseElemArr)
