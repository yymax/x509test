"""
This file contains the automatic test generation logic that generates test cases 
with exactly one basic attribute containing a long string. It is used to test
the overflow resistant capability of the other end. The main criteria for
passing this set of test cases is that the other end does not crash. The minor
criteria is that the other end aborts the connection.

@author: Calvin Jia Liang
Created on Oct 11, 2014
"""

from src.TestGroups import *


class TestOverflow:

    """
    TestOverflow constructor
    :param fqdn: fully quantifiable domain name
    :type  fqdn: string
    :param info: other information for the test session
    :type  info: Information object
    :param validCA: asssert if the CA of this test set is valid
    :type  validCA: boolean
    :returns: TestOverflow object
    """

    def __init__(self, fqdn, info, validCA=True):
        self.fqdn = fqdn
        self.info = copy.copy(info)
        self.info.metadata = None
        self.validCA = validCA

        self.step = 0
        self.filler = None
        self.cases = []

    """
    Build a list of overflow test cases based on basic attributes of the
    certificate; they are mostly negative test cases that has exactly one
    attribute containing a long string
    :returns: TestOverflow object
    """

    def build(self):
        baseCase = self.newCase("TestOverflowBaseCase")
        baseCase.testBuild(replace=True)
        cert = baseCase.getServCert().getCert()
        substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]

        cnt = self.countBasicAttr(cert)        
        for i in range(cnt):
            self.cases.append(self.newCase(self.getName(i))) 

        return self


    def getName(self, idx):
        return "Overflow_" + str(idx)

    """
    Get a new test case substrate
    :param name: name of the test case
    :type  name: string
    :returns: Certificate object
    """

    def newCase(self, name):
        metadata = TestMetadata(name, "", None, None, False, False,
                                overflow=True)

        substrate = TestCaseChained(self.fqdn, metadata, self.info, 2)
        substrate.includeAltName()
        substrate.getServCert().subject.commonName = self.fqdn
        substrate.getServCert().modifier.hasPreSign = True
        substrate.getServCert().modifier.preSign = self.preSign
        substrate.getServCert().addExtension(BasicConstraint(False))
        substrate.getServCert().addExtension(KeyUsage(keyEncipherment=True))
        substrate.getServCert().addExtension(ExtendedKeyUsage(serverAuth=True))
        
        if (not self.validCA):
            substrate.getFirstCA().security.certKey.build()
            substrate.getFirstCA().signer = CertSign(
                None,
                substrate.getFirstCA().security.certKey,
                substrate.getFirstCA().subject.getSubject())
        
        return substrate

    """
    Callback function to be executed before signature
    :param cert: certificate to be altered in asn1 format
    :type  cert: pyasn1 object
    :returns: pyasn1 object
    """

    def preSign(self, cert):
        parent, idx = self.getState(cert, queue.Queue(), 0)
        
        comp = parent.getComponentByPosition(idx)
        if (comp._value == b'\x05\x00'):
            comp._value = b'\x07\x01'
        string = self.getFiller()
        comp._value = comp._value[0:1] + bytes([len(string)]) + string
        
        self.step += 1
        return cert

    def getFiller(self):
        if (self.filler is None):
            self.filler = b''
            cnt = OVERFLOW_LENGTH
            
            for i in range(cnt):
                self.filler += bytes([cnt-i])
                
        return self.filler

    """
    Get the number basic attributes in the certificate
    :param cert: certificate to be counted
    :type  cert: pyasn1 object
    :returns: integer
    """
    
    def countBasicAttr(self, cert):
        cnt = 0
        self.step = 0
        
        while (True):
            parent, idx = self.getState(cert, queue.Queue(), 0)
            if (parent is None and idx is None):
                break
            self.step += 1
            cnt += 1
        
        self.step = 0
        return cnt-2 # exclude attr that only exist after signature

    """
    Get the component and index of the certificate to be altered
    :param cert: certificate to be altered
    :type  cert: pyasn1 object
    :param q: current queue
    :type  q: Queue object
    :param s: current step
    :type  s: integer
    :returns: asn1 object, integer
    """
    
    def getState(self, cert, q, s):
        if (q.empty()):
            q.put((cert, None, None))
        basic = False
        comp, parent, idx = q.get()

        if (comp.prettyPrint()[0:2] == '0x'):
            basic = True
            
        if (hasattr(comp, 'getComponentByPosition')):
            for i in range(len(comp)):
                sub = comp.getComponentByPosition(i)
                if (sub):
                    q.put((sub, comp, i))
            
        if (not basic or s != self.step):
            if (q.empty()):
                parent = idx = None
            elif (not basic):
                parent, idx = self.getState(cert, q, s)
            elif (s != self.step):
                parent, idx = self.getState(cert, q, s+1)
        
        return parent, idx
    
    """
    Get the list of test cases created from this object
    :returns: list of TestCase object
    """

    def getTestCases(self):
        return self.cases
