"""
This file holds the test expansion logic that expands certain marked
test cases into a new and separate test case. It does so by swapping
"body parts" from one test case to another test case. Probably the most
fragile part of the software. (This part of the code caused more crashes
than any other part of the software)

@author: Calvin Jia Liang
Created on Sep 6, 2014
"""

from src.TestCases import *

# TestExpander class that checks possible candidates and creates a new test
# case that is similar to the original one


class TestExpander:

    """
    TestExpander constructor
    :param fqdn: fully quantifiable domain name of the test case
    :type  fqdn: string
    :param info: other information for the test session
    :type  info: Information object
    :returns: TestExpander object
    """

    def __init__(self, fqdn, info):
        self.fqdn = fqdn
        self.info = info

        self.expansions = {}

    """
    Create a new chained test case by replacing the new case's first CA
    certificate with the candidate's server certificate
    :param case: test case to be examined
    :type  case: TestCase object
    :returns: TestCase object; None if candidate is not suitable for
              this expansion
    """

    def expandChainable(self, case):
        rtn = None

        if (case.isChainable() and not isinstance(case, TestCaseChained)):
            certName = getIntCAName(1)
            t = case.__class__(certName, self.info)
            t.metadata.name = getChainedName(t.metadata.name)

            t.metadata.ease = EASE_LOW
            t.metadata.severity = SEV_HIGH

            if (t.metadata.name == InvalidIntegrity.__name__):
                t.metadata.ease = EASE_HIGH

            newClass = type(t.metadata.name, ValidChained.__bases__,
                            dict(ValidChained.__dict__))
            rtn = newClass(self.fqdn, self.info)
            rtn = rtn.newTestCaseChained(self.fqdn, t.metadata, self.info,
                                         rtn.depth)
            rtn.replaceCA(0, t.getServCert())

            self.expansions[t.metadata.name] = t.metadata.name
            self.insertBaseClass(rtn, t)

        return rtn

    """
    Create a new altname test case by adding the candidate server certificate's
    CN to the AltName extension as a DNS-ID
    :param case: test case to be examined
    :type  case: TestCase object
    :returns: TestCase object; None if candidate is not suitable for
              this expansion
    """

    def expandAltExtend(self, case):
        rtn = None

        if (case.isAltExtend() and not isinstance(case, TestCaseAltName)):
            t = case.__class__(self.fqdn, self.info)
            t.metadata.name = getAltExtendedName(t.metadata.name)

            newClass = type(t.metadata.name, ValidAltName.__bases__,
                            dict(ValidAltName.__dict__))
            newClass.printMsg = TestCase.printMsg
            rtn = newClass(self.fqdn, self.info)
            rtn = rtn.newTestCaseAltName(self.fqdn, t.metadata, self.info)

            fieldName = 'IP' if (isIPAddr(rtn.fqdn) and rtn.info.useAddr)\
                        else 'DNS'
            rtn.getServCert().getExtension(SubjectAltName).\
                field[fieldName][0] = t.getServCert().security.fqdn

            self.expansions[t.metadata.name] = t.metadata.name
            self.insertBaseClass(rtn, t)

        return rtn

    """
    Get if the class in question is created as the result of the expansion
    process; this function is used to make sure that the same expanded test
    does not get build twice (which happens because type() inserts a new
    class entry during runtime)
    :param classObj: test case's class to be examined
    :type  classObj: Class object
    :returns: boolean
    """

    def isExpansion(self, classObj):
        return hasattr(classObj, '__name__') and classObj.__name__ in\
            self.expansions

    """
    Get a list of extensions for the test case; new expansions must be included
    to this function for it to become active
    :param case: test case to be examined
    :type  case: TestCase object
    :returns: list of TestCase object
    """

    def getExpansions(self, case):
        rtn = []

        chain = self.expandChainable(case)
        alt = self.expandAltExtend(case)

        if (chain):
            rtn.append(chain)
        if (alt):
            rtn.append(alt)
        return rtn

    """
    Insert the parent class of one object to another
    :param baseObj: destination of the insertion
    :type  baseObj: TestCase object
    :param inObj: source of the insertion
    :type  inObj: TestCase object
    """

    def insertBaseClass(self, baseObj, inObj):
        if (not isinstance(baseObj, inObj.__class__.__bases__[0]) and
                not isinstance(inObj, baseObj.__class__.__bases__[0])):
            baseObj.__class__.__bases__ += (inObj.__class__.__bases__[0],)
