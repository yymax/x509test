"""
This file contains the terminal, or leaf, test case classes. They are the
"bread and butter" of the software. Each class represents a test case under
the group defined by its ancestors. Each test case begins by creating a
TestMetadata object to describe itself. Then, the test case calls its parent
constructor to build a basic test case along with some additional
functions provided by the ancestors. Then, depending on the test case, further
modification can be made. Cases that are suitable to be expanded into
another case can do so by changing its attributes in TestMetadata
object.

NOTE: No certificate is written to hard disk by merely calling the constructor.
      The actual creation of certificates is performed once the build() method
      is called (by TestSet). Same is true for the actual keys used in the
      signing process. Those are design features that improves the performance
      of the software, as well as increases the flexibility on modifying
      components of the test case during construction.

@author: Calvin Jia Liang
Created on May 29, 2014
"""

# ############################################################################
# Parameter Descriptions
#
# fqdn - string; fully quantifiable domain name
# metadata - Metadata object; check definition in the Metadata class
# info - Information object; check definition in the Information class
# depth - integer; number of certificates in the chain (including server
#         certificate but excluding root CA)
#
#
# Basic Terminology
#
# certificate - an asn1 data structure specified by the RFC5280;
#               mainly refers to the X509 version 3 certificate
# basic certificate - certificate without any extension
# test certificate - certificate that potentially contains flaws
# server certificate - certificate used to bind the identify and public key
#                      of the target system (usually a SSL/TLS server)
# CA - certificate authority that acts as a trusted third party in CA-PKI model;
#      it has the power to sign other certificates
# root CA - certificate authority that has a self-signed certificate installed
#           in the system's trust store
# intermediate CA - certificate authority that is signed by another CA
# edge/leaf CA - certificate authority that signs the server certificate
# CN - common name in the subject distinguish name field
#
# More background information available in RFC5280, RFC6125, RFC 5246, etc.
# ############################################################################


from src.TestGroups import *


# Basic Valid Cert Test ####################################################

class ValidCert(TestCase):

    """A valid certificate, signed directly by the root CA, that contains its
    fqdn in the CN."""
    
    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, None, None, None,
                                True, True)
        super(self.__class__, self).__init__(fqdn, metadata, info)

# Immediate Cert Tests ####################################################

class InvalidName(TestCaseImmed):

    """A basic certificate that contains an incorrect fqdn in the CN."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4",
                                SEV_MED, EASE_HIGH, altextend=True)
        super(self.__class__, self).__init__(getInvalidDomain(fqdn), metadata,
                                             info)

class InvalidNameNull(TestCaseImmed):

    """A basic certificate that contains a null-prefix attack in the CN."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4",
                                SEV_MED, EASE_MED)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().modifier.hasPreSign = True
        self.getServCert().modifier.preSign = self.preSign

    def preSign(self, asnObj):
        (asnObj
         .getComponentByPosition(0)
         .getComponentByName('subject')
         .getComponentByPosition(0)
         .getComponentByPosition(5)
         .getComponentByPosition(0)
         .setComponentByName('value',
                             rfc2459.TeletexCommonName(
                                 getInvalidNullDomain(self.fqdn).encode('utf-8'))))
        return asnObj



class InvalidNotBefore(TestCaseImmed):

    """A basic certificate that contains a NotBefore time after now."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.1.2.5",
                                SEV_MED, EASE_HIGH, chainable=True)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().security.notBefore = HOUR_DISCREPANCY


class InvalidNotAfter(TestCaseImmed):

    """A basic certificate that contains a NotAfter time before now."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.1.2.5",
                                SEV_MED, EASE_HIGH, chainable=True)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().security.notAfter = -HOUR_DISCREPANCY


class InvalidIntegrity(TestCaseImmed):

    """A basic certificate that has been modified after its signature."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "PKCS7", SEV_MED,
                                EASE_HIGH, chainable=True)
        super(self.__class__, self).__init__(getInvalidDomain(fqdn), metadata,
                                             info)

        self.fqdnValid = fqdn
        self.getServCert().modifier.hasPostSign = True
        self.getServCert().modifier.postSign = self.postSign

    def postSign(self, asnObj):
        (asnObj
         .getComponentByPosition(0)
         .getComponentByName('subject')
         .getComponentByPosition(0)
         .getComponentByPosition(5)
         .getComponentByPosition(0)
         .setComponentByName('value', rfc2459.TeletexCommonName(self.fqdnValid.encode('utf-8'))))
        return asnObj


class InvalidExtendedKeyUsage(TestCaseImmed):

    """A certificate that has an unsuitable value in the extended key usage
    extension (serverAuth=false)."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.12",
                                SEV_LOW, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().addExtension(
            ExtendedKeyUsage(
                serverAuth=False,
                clientAuth=True,
                codeSigning=True,
                emailProtection=True,
                timeStamping=True))


class InvalidKeyUsage(TestCaseImmed):

    """A certificate that has an unsuitable value in the key usage extension
    (cRLSign=true)."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.3",
                                SEV_LOW, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().addExtension(KeyUsage(cRLSign=True))


class InvalidCriticalExtension(TestCaseImmed):

    """A certificate that has an non-standard critical extension entry."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2",
                                SEV_HIGH, EASE_MED, chainable=True)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().modifier.hasPreSign = True
        self.getServCert().modifier.preSign = self.preSign
        self.getServCert().addExtension(ExtendedKeyUsage(serverAuth=True,
                                                         critical=True))

    def preSign(self, asnObj):
        (asnObj
         .getComponentByPosition(0)
         .getComponentByName('extensions')
         .getComponentByPosition(0)
         .setComponentByName('extnID',
            rfc2459.univ.ObjectIdentifier('1.3.6.1.4.1.11129.2.5.1')))
        return asnObj


class InvalidSelfSign(TestCaseImmed):

    """A self-signed certificate."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 6.1.4",
                                SEV_HIGH, EASE_HIGH)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().security.certKey.build()
        self.getServCert().signer = CertSign(
            None,
            self.getServCert().security.certKey,
            self.getServCert().subject.getSubject())


# Chained Cert Tests ####################################################

class ValidChained(TestCaseChained):

    """A valid chain of certificates.
    """

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280",
                                None, None, True, True)
        super(self.__class__, self).__init__(fqdn, metadata, info)


class MissingIntCAExtensions(TestCaseChained):

    """A chain of certificates where the first intermediate CA is missing a
    basic constraint extension.
    """

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.9",
                                SEV_HIGH, EASE_HIGH)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().removeExtension(BasicConstraint)
        self.getFirstCA().removeExtension(KeyUsage)




class InvalidIntCAFlag(TestCaseChained):

    """A chain of certificates where the first intermediate CA has a basic
    constraint extension that is marked to false.
    """

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.9",
                                SEV_HIGH, EASE_HIGH)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().getExtension(BasicConstraint).ca = False
        self.getFirstCA().removeExtension(KeyUsage)


class ValidIntCALen(TestCaseChained):

    """A valid chain of certificates where the first intermediate CA and
    edge CA have basic constraint extensions that include pathLen of 5 and 0,
    respectively.
    """

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.9",
                                SEV_LOW, EASE_LOW, False, True)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().getExtension(BasicConstraint).pathLen = 5
        self.getEdgeCA().getExtension(BasicConstraint).pathLen = 0



class InvalidIntCALen(TestCaseChained):

    """A chain of certificates where the first and second intermediate CA
    have basic constraint extensions that both include pathLen of 1.
    """

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.9",
                                SEV_HIGH, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().getExtension(BasicConstraint).pathLen = 1
        self.getSecondCA().getExtension(BasicConstraint).pathLen = 1



class InvalidIntCAKeyUsage(TestCaseChained):

    """A chain of certificates where the first intermediate CA has keyCertSign
    marked as false in the key usage extension.
    """

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.3",
                                SEV_HIGH, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().getExtension(KeyUsage).field['keyCertSign'] = False
        self.getFirstCA().getExtension(KeyUsage).field['digitalSignature'] = True
        self.getFirstCA().getExtension(KeyUsage).field['keyEncipherment'] = True

class MissingIntCABasicConstraintWithCertSign(TestCaseChained):

    """A chain of certificates where the first intermediate CA has keyCertSign
    marked as true in the key usage extension but lacks the basic constraint
    extension entirely."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.3",
                                SEV_HIGH, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().removeExtension(BasicConstraint)


class InvalidIntCAVersionOne(TestCaseChained):

    """A chain of certificates where the first intermediate CA is a basic version 1
    certificate."""

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 6.1.4(k)",
                                SEV_HIGH, EASE_HIGH)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().security.version = 0x00
        self.getFirstCA().extensions = []

# A chain of certificates where the first intermediate CA is a basic version 2
# certificate


class InvalidIntCAVersionTwo(TestCaseChained):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 6.1.4(k)",
                                SEV_HIGH, EASE_HIGH)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().security.version = 0x01
        self.getFirstCA().extensions = []

# A chain of certificates where the first intermediate CA is signed by the
# edge CA


class InvalidIntCALoop(TestCaseChained):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 6.1.4",
                                SEV_HIGH, EASE_HIGH)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getEdgeCA().security.certKey.build()
        self.getFirstCA().signer = CertSign(
            None,
            self.getEdgeCA().security.certKey,
            self.getEdgeCA().subject.getSubject())

# A chain of certificates where the first intermediate CA is self-signed


class InvalidIntCASelfSign(TestCaseChained):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 6.1.4",
                                SEV_HIGH, EASE_HIGH)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getFirstCA().security.certKey.build()
        self.getFirstCA().signer = CertSign(
            None,
            self.getFirstCA().security.certKey,
            self.getFirstCA().subject.getSubject())

# Wildcard Cert Tests ####################################################

# A valid wildcard certificate.


class ValidWildcard(TestCaseWildcard):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.3",
                                None, None, True, True)

        if (len(fqdn.split('.')) < 3):
            raise Exception("Input fqdn {} has too few components to generate"
                            " wildcard tests".format(fqdn))
        fqdnArr = fqdn.split('.')
        wildcard = "*." + '.'.join(fqdnArr[1:])

        super(self.__class__, self).__init__(wildcard, metadata, info)

# A wildcard certificate that tries to extend its matching effect to its left.
# For example, it tries to match www.tls.test with *.test


class InvalidWildcardLeft(TestCaseWildcard):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.3",
                                SEV_MED, EASE_HIGH, altextend=True)

        fqdnArr = fqdn.split('.')
        wildcard = "*." + '.'.join(fqdnArr[2:])

        super(self.__class__, self).__init__(wildcard, metadata, info)

# A wildcard certificate that has wildcard character in the mid-segment of
# the fqdn.
# For example, it tries to match www.tls.test with www.*.test


class InvalidWildcardMid(TestCaseWildcard):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.3",
                                SEV_MED, EASE_MED, altextend=True)

        fqdnArr = fqdn.split('.')
        wildcard = fqdnArr[0] + ".*." + '.'.join(fqdnArr[2:])

        super(self.__class__, self).__init__(wildcard, metadata, info)

# A wildcard certificate that has wildcard character in the middle of the fqdn.
# For example, it tries to match www.tls.test with www.*s.test


class InvalidWildcardMidMixed(TestCaseWildcard):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.3",
                                SEV_MED, EASE_MED, altextend=True)

        fqdnArr = fqdn.split('.')
        wildcard = fqdnArr[0] + ".*" + fqdnArr[1][-1] + "." +\
            '.'.join(fqdnArr[2:])

        super(self.__class__, self).__init__(wildcard, metadata, info)

# A wildcard certificate that has wildcard characters in all segments.
# For example, it tries to match www.tls.test with *.*.*


class InvalidWildcardAll(TestCaseWildcard):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.3",
                                SEV_MED, EASE_MED, altextend=True)

        fqdnArr = fqdn.split('.')
        for i in range(len(fqdnArr)):
            fqdnArr[i] = "*"
        wildcard = '.'.join(fqdnArr[:])

        super(self.__class__, self).__init__(wildcard, metadata, info)

# A wildcard certificate that has a single wildcard character.
# For example, it tries to match www.tls.test with *


class InvalidWildcardSingle(TestCaseWildcard):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.3",
                                SEV_MED, EASE_MED, altextend=True)

        wildcard = "*"

        super(self.__class__, self).__init__(wildcard, metadata, info)


# Alternate Name Cert Tests #################################################

# A valid certificate with a valid AltName but incorrect CN
class ValidAltName(TestCaseAltName):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.4",
                                None, None, True, True)
        super(self.__class__, self).__init__(fqdn, metadata, info)

    def printMsg(self, passed):
        TestCase.printMsg(self, passed)
        if (not passed):
            self.info.log("* NOTE: checking of SubjectAltName instead" +
                          " of Common Name is encouraged; see RFC6125 1.5")

# A certificate with a invalid AltName but correct CN


class InvalidNameAltNameWithSubj(TestCaseAltName):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.4",
                                SEV_LOW, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().subject.commonName = fqdn
        altNames = self.getServCert().getExtension(SubjectAltName).field['DNS']
        for i in range(len(altNames)):
            altNames[i] = getInvalidDomain(fqdn)

# A certificate with a null-prefix attack in its AltName


class InvalidNameNullAltName(TestCaseAltName):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.4",
                                SEV_MED, EASE_MED)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().modifier.hasPreSign = True
        self.getServCert().modifier.preSign = self.preSign
        self.trail = "x" + INVALID_TRAIL
        self.getServCert().getExtension(SubjectAltName).field['DNS'][0] = fqdn\
            + self.trail

    def preSign(self, asnObj):
        val = asnObj.getComponentByPosition(0).getComponentByName('extensions')\
            .getComponentByPosition(0).getComponentByName('extnValue')
        arr = bytearray(val._value)
        arr[-len(self.trail)] = 0
        val._value = bytes(arr)
        asnObj.getComponentByPosition(0).getComponentByName('extensions').\
            getComponentByPosition(0).setComponentByName('extnValue', val)
        return asnObj

# A certificate with a null-prefix attack in both its AltName and CN


class InvalidNameNullAltNameAndSubj(TestCaseAltName):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.4",
                                SEV_MED, EASE_MED)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().modifier.hasPreSign = True
        self.getServCert().modifier.preSign = self.preSign
        self.trail = "x" + INVALID_TRAIL
        self.getServCert().getExtension(SubjectAltName).field['DNS'][0] = \
            fqdn + self.trail

    def preSign(self, asnObj):
        val = asnObj.getComponentByPosition(0).getComponentByName('extensions')\
            .getComponentByPosition(0).getComponentByName('extnValue')
        arr = bytearray(val._value)
        arr[-len(self.trail)] = 0
        val._value = bytes(arr)
        asnObj.getComponentByPosition(0).getComponentByName('extensions').\
            getComponentByPosition(0).setComponentByName('extnValue', val)

        asnObj.getComponentByPosition(0).getComponentByName('subject'). getComponentByPosition(0).getComponentByPosition(
            5). getComponentByPosition(0).setComponentByName('value', rfc2459.TeletexCommonName(getInvalidNullDomain(self.fqdn). encode('utf-8')))

        return asnObj

# A certificate with a null-prefix attack in its AltName but a correct CN


class InvalidNameNullAltNameWithSubj(TestCaseAltName):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC6125 6.4.4",
                                SEV_LOW, EASE_MED)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.getServCert().subject.commonName = fqdn
        self.getServCert().modifier.hasPreSign = True
        self.getServCert().modifier.preSign = self.preSign
        self.trail = "x" + INVALID_TRAIL
        self.getServCert().getExtension(SubjectAltName).field['DNS'][0] = \
            fqdn + self.trail

    def preSign(self, asnObj):
        val = asnObj.getComponentByPosition(0).getComponentByName('extensions')\
            .getComponentByPosition(0).getComponentByName('extnValue')
        arr = bytearray(val._value)
        arr[-len(self.trail)] = 0
        val._value = bytes(arr)
        asnObj.getComponentByPosition(0).getComponentByName('extensions').\
            getComponentByPosition(0).setComponentByName('extnValue', val)
        return asnObj

# Name Constraint Cert Tests #################################################

# A valid chain with a permitted subtree of ".test" in the first intermediate CA
# and an excluded subtree of an incorrect fqdn in the second intermediate CA.


class ValidNameConstraint(TestCaseNameConstraint):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.10",
                                None, None, True, True)

        if (len(fqdn.split('.')) < 2):
            raise Exception("Input fqdn %s has too few tokens to generate" +
                            " name constraints tests" % fqdn)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.appendPermit(self.getFirstCA(), '.' + fqdn.split('.')[-1])
        self.appendExclude(self.getSecondCA(), getInvalidDomain(fqdn))

# A chain with an excluded subtree of the fqdn's network name in the
# first intermediate CA.


class InvalidNameConstraintExclude(TestCaseNameConstraint):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.10",
                                SEV_MED, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.appendExclude(self.getFirstCA(), '.' + fqdn.split('.')[-1])

# A chain with an excluded subtree of any in the first intermediate CA.
# class InvalidNameConstraintPermitNone(TestCaseNameConstraint):
#     def __init__(self, fqdn, info):
#         metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.10",\
#                                  SEV_MED, EASE_LOW);
#         super(self.__class__, self).__init__(fqdn, metadata, info);
#
#         self.appendPermit(self.getFirstCA(), "");

# A chain with a permitted subtree of an incorrect fqdn's network name in the
# first intermediate CA.


class InvalidNameConstraintPermit(TestCaseNameConstraint):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.10",
                                SEV_MED, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.appendPermit(self.getFirstCA(), '.' + fqdn.split('.')[-1] + "x")

# A chain with a permitted subtree of a truncated fqdn's network name in the
# first intermediate CA.


class InvalidNameConstraintPermitRight(TestCaseNameConstraint):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.10",
                                SEV_MED, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.appendPermit(self.getFirstCA(), '.' + fqdn.split('.')[-2])

# A chain with a permitted subtree of ".test" in the first intermediate CA and
# an excluded subtree of ".test" in the second intermediate CA.


class InvalidNameConstraintPermitThenExclude(TestCaseNameConstraint):

    def __init__(self, fqdn, info):
        metadata = TestMetadata(self.__class__.__name__, "RFC5280 4.2.1.10",
                                SEV_MED, EASE_LOW)
        super(self.__class__, self).__init__(fqdn, metadata, info)

        self.appendPermit(self.getFirstCA(), '.' + fqdn.split('.')[-1])
        self.appendExclude(self.getSecondCA(), '.' + fqdn.split('.')[-1])
