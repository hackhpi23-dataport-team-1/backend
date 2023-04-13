import xml.etree.ElementTree as ET
# from lxml import etree
from io import StringIO
import sys,os
import csv

os.chdir(os.path.dirname(os.path.abspath(__file__)))

EVENT_PARSE = 1
EVENTDATA_PARSE = 2

typeArr = {"Event": EVENT_PARSE, "EventData" : EVENTDATA_PARSE}

def newObject(tag):
    """
    given the tag, to decide whether it is a nested element or a new object
    """
    if tag in typeArr:
        return typeArr[tag]
    else:
        return None
    
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



def parseTrafo(filepath):
    """
    given filepath of a xml file (`EQ.xml`)
    parse the info for the transformer
    -----
    Parameters:
    ------
    filepath: str
    path to the xml file
    -----
    Return:
    ------
    A dictionary with the name of the trafo as key, values are a dictionary saving the info for the trafo
    """

    ## check if the file ending with `_EQ.xml`


    ## remove the prefix 
    root = parseElem(filepath)

    ## parse the trafo
    trafoDict = {}
    for child in root:
        if (child.tag == "PowerTransformer"):
            print("it is PowerTransformer")
            print(child.attrib)
            for subnode in child:
                if (subnode.tag == "IdentifiedObject.name"):
                    trafoDict[subnode.text] = {}
                
        if (child.tag == "PowerTransformerEnd"):
            print("it is PowerTransformerEnd")
            print(child.attrib)
            for subnode in child:
                if (subnode.tag == "IdentifiedObject.name"):
                    trafoName = subnode.text
                if (subnode.tag == "PowerTransformerEnd.ratedS"):
                    ratedS = float(subnode.text)
                    trafoDict[trafoName]["ratedS"] = ratedS
            print("Dict[trafoName], trafoName:" + trafoName)
            print(trafoDict[trafoName])
    return trafoDict


if __name__ == "__main__":
    temp_parseElemArr = parseElem("../exampleData/twoEvents.xml")
    print(temp_parseElemArr)