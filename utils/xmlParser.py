import xml.etree.ElementTree as ET
# from lxml import etree
from io import StringIO
import sys,os
import csv

os.chdir(os.path.dirname(os.path.abspath(__file__)))

def moveNS(filepath):
    """
    given the filepath of a xml file,
    remove all the namespace,
    return the root node
    -----
    Parameters:
    ------
    filepath: str
    path to the xml file

    return:

    - Event:
    
    type: Event
    level: System
    subdict

    data: EventData
    


    """ 
    it = ET.iterparse(filepath,events=("start","end"))
    # it = ET.parse(filepath)
    # it = it.getroot()
    # it = iter(it)
    for temp_, el in it:
        prefix, has_namespace, postfix = el.tag.partition('}')
        if has_namespace:
            el.tag = postfix  # strip all namespaces
        if el.tag == "Event":
            # event type

        for at in list(el.attrib.keys()): # strip namespaces of attributes too
            if '}' in at:
                newat = at.split('}', 1)[1]
                el.attrib[newat] = el.attrib[at]
                del el.attrib[at]       
    return it.root



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
    root = moveNS(filepath)

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
    moveNS("../exampleData/twoEvents.xml")