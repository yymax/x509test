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

    NAME_TABLE = ["SignatureAlgorithm", "SubjectAltName", 
                  "BasicConstraint", "KeyUsage",
                  "ExtendedKeyUsage", "IssuerC", "IssuerST",
                  "IssuerL", "IssuerO", "IssuerOU", "IssuerCN", 
                  "IssuerEmail", "SubjectC", "SubjectST",
                  "SubjectL", "SubjectO", "SubjectOU", "SubjectCN", 
                  "SubjectEmail"]

    """
    TestOverflow constructor
    :param fqdn: fully quantifiable domain name
    :type  fqdn: string
    :param info: other information for the test session
    :type  info: Information object
    :param length: byte length of the overflow filler
    :type  length: integer
    :param validCA: asssert if the CA of this test set is valid
    :type  validCA: boolean
    :returns: TestOverflow object
    """

    def __init__(self, fqdn, info, length=DEFAULT_OVERFLOW_LENGTH, validCA=True):
        self.fqdn = fqdn
        self.info = copy.copy(info)
        self.info.metadata = None
        self.overflowLen = length
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
        baseCase = self.newSubstrate("TestOverflowBaseCase")
        baseCase.getServCert().modifier.hasPreSign = False
        baseCase.testBuild(replace=True)
        cert = baseCase.getServCert().getCert()
        substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]

        cnt = self.countBasicAttr(cert)
        if (cnt != len(TestOverflow.NAME_TABLE)):
            raise Exception("Attribute count and name table length mismatch")
        
        tempCases = []        
        for i in range(cnt):
            tempCases.append(self.newSubstrate(self.getName(i))) 
        tempCases.append(self.getLongChain())
        tempCases.append(self.getLongExtension())
#         tempCases.append(self.getLongAttribute())
        tempCases.append(self.getLongOID())

        for c in tempCases:
            if (not self.validCA):
                c.getFirstCA().selfSign()
            self.cases.append(c)
            
        return self


    def getName(self, idx):
        return "Long" + TestOverflow.NAME_TABLE[idx]

    """
    Get a new test case substrate
    :param name: name of the test case
    :type  name: string
    :returns: Certificate object
    """

    def newSubstrate(self, name):
        metadata = TestMetadata(name, "", None, None, False, False,
                                overflow=True)

        substrate = TestCaseChained(self.fqdn, metadata, self.info, 2)
        substrate.includeAltName()
        substrate.getServCert().subject.commonName = self.fqdn
        substrate.getServCert().addExtension(BasicConstraint(False))
        substrate.getServCert().addExtension(KeyUsage(keyEncipherment=True))
        substrate.getServCert().addExtension(ExtendedKeyUsage(serverAuth=True))
        
        substrate.getServCert().modifier.hasPreSign = True
        substrate.getServCert().modifier.preSign = self.preSignSubstrate

        return substrate

    """
    Callback function to be executed before signature
    :param cert: certificate to be altered in asn1 format
    :type  cert: pyasn1 object
    :returns: pyasn1 object
    """

    def preSignSubstrate(self, cert):
        parent, idx = self.getState(cert, queue.Queue(), 0)
        
        comp = parent.getComponentByPosition(idx)
        if (comp._value == b'\x05\x00'):
            comp._value = b'\x07\x01'
        string = self.getFiller(self.overflowLen)
        comp._value = comp._value[0:1] + string
        
        self.step += 1
        return cert

    """
    Get a long chained test case
    :returns: Certificate object
    """

    def getLongChain(self):
        name = "LongChain"
        metadata = TestMetadata(name, "", None, None, False, False,
                                overflow=True)

        substrate = TestCaseChained(self.fqdn, metadata, self.info, 
                                    OVERFLOW_CHAIN_LEN)
        substrate.includeAltName()

        return substrate

    """
    Get a long extension test case
    :returns: Certificate object
    """

    def getLongExtension(self):
        name = "LongExtension"
        metadata = TestMetadata(name, "", None, None, False, False,
                                overflow=True)

        substrate = TestCaseChained(self.fqdn, metadata, self.info, 2)
        substrate.includeAltName(critical=False)
        base = substrate.getServCert().extensions[0]
        for _ in range(OVERFLOW_EXT_LEN):
            substrate.getServCert().extensions.append(base)

        return substrate

#     """
#     Get a long attribute test case
#     :returns: Certificate object
#     """
# 
#     def getLongAttribute(self):
#         name = "Overflow_LongAttribute"
#         metadata = TestMetadata(name, "", None, None, False, False,
#                                 overflow=True)
# 
#         substrate = TestCaseChained(self.fqdn, metadata, self.info, 2)
#         substrate.includeAltName()
#         substrate.getServCert().subject.commonName = self.fqdn
#         
#         substrate.getServCert().modifier.hasPreSign = True
#         substrate.getServCert().modifier.preSign = self.preSignAttribute
# 
#         return substrate
# 
#     """
#     Callback function to be executed before signature
#     :param cert: certificate to be altered in asn1 format
#     :type  cert: pyasn1 object
#     :returns: pyasn1 object
#     """
# 
#     def preSignAttribute(self, cert):
#         comp = cert.getComponentByPosition(0).getComponentByName('extensions').\
#             getComponentByPosition(0).getComponentByName('extnValue')
#         string = self.getFiller(self.overflowLen*OVERFLOW_MEGA_MUL)
#         comp._value = comp._value[0:1] + string
# 
#         return cert

    """
    Get a long attribute test case
    :returns: Certificate object
    """

    def getLongOID(self):
        name = "LongOID"
        metadata = TestMetadata(name, "", None, None, False, False,
                                overflow=True)

        substrate = TestCaseChained(self.fqdn, metadata, self.info, 2)
        substrate.includeAltName(critical=False)
        
        substrate.getServCert().modifier.hasPreSign = True
        substrate.getServCert().modifier.preSign = self.preSignOID

        return substrate

    """
    Callback function to be executed before signature
    :param cert: certificate to be altered in asn1 format
    :type  cert: pyasn1 object
    :returns: pyasn1 object
    """

    def preSignOID(self, cert):
        oid = ((NONSTANDARD_OID + '.') * OVERFLOW_OID_MUL)[:-1]
        (cert
         .getComponentByPosition(0)
         .getComponentByName('extensions')
         .getComponentByPosition(0)
         .setComponentByName('extnID',
            rfc2459.univ.ObjectIdentifier(oid)))
        return cert


    def getFiller(self, size):
        bLen = math.ceil((math.log(size+1)/math.log(2))/8)
        filler = bytes([128+bLen]) + \
          size.to_bytes(bLen, 'big') + b'a'*size
                
        return filler


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
