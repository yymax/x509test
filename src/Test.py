"""
This file contains the root (abstract) class and its peripheral classes.
Class TestCase is the root node in the test case inheritance hierarchy.
Class TestCase provides the core functionality for all test cases.
The peripheral classes supply information to the TestCase object.

@author: Calvin Jia Liang
Created on May 15, 2014
"""

from src.Certificate import *

# Metadata class that describes a test case and controls the behavior of the
# corresponding connection.


class TestMetadata:

    """
    TestMetadata constructor
    :param name: name of the test case
    :type  name: string
    :param ref: authentic reference that describe the correct behavior
    :type  ref: string
    :param severity: severity if the test case failed
    :type  severity: Definition macro
    :param ease: ease of execution
    :type  ease: Definition macro
    :param isCritical: assert if dependency check
    :type  isCritical: boolean
    :param isValid: assert if valid or positive test case
    :type  isValid: boolean
    :param chainable: assert if test case can be chained
    :type  chainable: boolean
    :param altextend: assert if test case can be altname extended
    :type  altextend: boolean
    :param functional: assert if functionality test case (inherently positive)
    :type  functional: boolean
    :param sslVer: the SSL/TLS handshake used in this connection
    :type  sslVer: pyOpenSSL macro
    :param caPathPrefix: the path prefix of the root CA
    :type  caPathPrefix: string
    :param testDir: the top level test directory path
    :type  testDir: string
    :param suite: the acceptable crypto suite used in this connection
    :type  suite: string
    :returns: TestMetadata object
    """

    def __init__(self, name, ref, severity, ease, isCritical=False,
                 isValid=False, chainable=False, altextend=False,
                 functional=False, sslVer=None, caPathPrefix=DEFAULT_CA_PREFIX,
                 testDir=DEFAULT_CERT_DIR, suite=DEFAULT_SUITE):

        self.name = name
        self.ref = ref
        self.severity = severity
        self.ease = ease
        self.isCritical = isCritical
        self.isValid = isValid

        self.suite = suite
        self.sslVer = sslVer

        self.chainable = chainable
        self.altextend = altextend
        self.functional = functional

        self.caPathPrefix = caPathPrefix
        self.testDir = testDir

    """
    Write all metadata attributes to file
    :param path: path of the metadata file
    :type  path: string
    """

    def write(self, path=None):
        if (not path):
            path = os.path.join(self.testDir, self.name, DEFAULT_METADATA_NAME)

        with open(path, 'w+') as f:
            f.write("%s=%s\n" % ("name", self.name))
            f.write("%s=%s\n" % ("ref", self.ref))
            f.write("%s=%s\n" % ("severity", self.severity))
            f.write("%s=%s\n" % ("ease", self.ease))
            f.write("%s=%s\n" % ("isCritical", self.isCritical))
            f.write("%s=%s\n" % ("isValid", self.isValid))
            f.write("%s=%s\n" % ("suite", self.suite))
            f.write("%s=%s\n" % ("sslVer", self.sslVer))
            f.write("%s=%s\n" % ("chainable", self.chainable))
            f.write("%s=%s\n" % ("altextend", self.altextend))
            f.write("%s=%s\n" % ("functional", self.functional))
            f.write("%s=%s\n" % ("caPathPrefix", self.caPathPrefix))
            f.write("%s=%s\n" % ("testDir", self.testDir))

    def load(self, path=None):
        pass

# Information class that provides user and system setting information
# to all test cases.


class Information:

    """
    Information constructor
    :param log: output stream callback function
    :type  log: Function object
    :param caPathPrefix: the path prefix of the signer
    :type  caPathPrefix: string
    :param testDir: the top level test directory path
    :type  testDir: string
    :param caPassword: password for the signer's key file
    :type  caPassword: string
    :param addr: IP address of the connection
    :type  addr: string
    :param port: port number of the connection
    :type  port: integer
    :param kSize: length of the key
    :type  kSize: integer
    :param metadata: substitute Metadata object (used in Expander only)
    :type  metadata: Metadata object
    :returns: Information object
    """

    def __init__(self, log, caPathPrefix=DEFAULT_CA_PREFIX,
                 testDir=DEFAULT_CERT_DIR, caPassword=None, addr=None,
                 port=None, kSize=None, metadata=None):

        self.caPathPrefix = caPathPrefix
        self.testDir = testDir
        self.caPassword = caPassword

        self.addr = addr
        self.port = port
        self.kSize = kSize

        self.metadata = metadata
        self.log = log

# Test case class that represents an individual test case.


class TestCase:

    """
    TestCase constructor
    :param fqdn: fully quantifiable domain name of the test case
    :type  fqdn: string
    :param metadata: metadata accompanies the test case
    :type  metadata: TestMetadata object
    :param info: other information for the test session
    :type  info: Information object
    :param depth: number of certificates chained (including the leaf)
    :type  depth: integer
    :returns: TestCase object
    """

    def __init__(self, fqdn, metadata, info, depth=1):
        self.newTestCase(fqdn, metadata, info, depth)

    def newTestCase(self, fqdn, metadata, info, depth):
        self.fqdn = fqdn
        self.metadata = info.metadata if info.metadata else metadata
        self.info = info
        self.depth = depth

        if (info.caPathPrefix):
            self.metadata.caPathPrefix = info.caPathPrefix
        if (info.testDir):
            self.metadata.testDir = info.testDir

        self.certs = []
        pKey = pSubj = None
        i = 1
        while (depth > 0):
            extensions = []

            if (depth > 1):
                certName = getIntCAName(i)
                certPathPrefix = os.path.join(self.getCertDir(), certName)
                extensions.append(BasicConstraint(True))
                extensions.append(KeyUsage(keyCertSign=True, cRLSign=True))
            else:
                certName = fqdn
                certPathPrefix = os.path.join(self.getCertDir(),
                                              self.metadata.name)

            if (self.getDepth() == 0):
                signer = CertSign(self.getCAPathPrefix(),
                                  keyPassword=self.info.caPassword)
            else:
                signer = CertSign(None, pKey, pSubj)

            if (info.kSize):
                security = CertSec(certName, kSize=info.kSize)
            else:
                security = CertSec(certName)

            cert = Certificate(certPathPrefix, signer, security, extensions)
            pKey = cert.security.certKey
            pSubj = cert.subject.getSubject()
            self.certs.append(cert)

            depth -= 1
            i += 1

        return self

    """
    Test preparation that make sure the destination folder is ready
    :param replace: assert if erasing all previous test case files
    :type  replace: boolean
    :returns: boolean
    """

    def testPrep(self, replace=False):
        if (replace and os.path.exists(self.getCertDir())):
            shutil.rmtree(self.getCertDir())
        if (not os.path.exists(self.getCertDir())):
            os.mkdir(self.getCertDir())
            replace = True
        return replace

    """
    Build test if necessary
    :param replace: assert if erasing previous test case files
    :type  replace: boolean
    """

    def testBuild(self, replace=False):
        if (self.testPrep(replace)):
            self.procedure()

    """
    Build all certificates in the test case by calling corresponding build()
    methods and write the key file of the last certificate to hard disk
    """

    def procedure(self):
        lastCert = None
        i = 1

        for cert in self.certs:
            cert.security.build()
            cert.signer.build()
            cert = self.preCertBuild(cert, i)
            cert.build()
            lastCert = cert
            i += 1

        lastCert.writeKey(self.getKeyPath())
        self.metadata.write()

    """
    Function to override if the test case requires certain procedure to be
    done immediately before calling build() of the certificate
    :param cert: the certificate in question
    :type  cert: Certificate object
    :param idx: index of the CA in the chain
    :type  idx: integer
    :returns: Certificate object
    """

    def preCertBuild(self, cert, idx):
        return cert

    """
    Replace the specified CA with another certificate; BasicConstraint and
    KeyUsage extensions will be correctly added to form a valid CA
    :param idx: index of the CA in the chain to be replaced
    :type  idx: integer
    :param cert: the successor certificate
    :type  cert: Certificate object
    """

    def replaceCA(self, idx, cert):
        cert.certPathPrefix = os.path.join(self.getCertDir(),
                                           self.certs[idx].security.fqdn)
        cert.addExtension(BasicConstraint(True))
        cert.addExtension(KeyUsage(keyCertSign=True, cRLSign=True))

        self.certs[idx] = cert
        self.certs[idx + 1].signer.signKey = cert.security.certKey

    """
    Add AltName extensions to all certificates in the test case; the new
    altname follows the DNS-ID of the fqdn
    :param critical: assert if critical extension
    :type  critical: boolean
    """

    def includeAltName(self, critical=True):
        for cert in self.certs:
            try:
                cert.addExtension(SubjectAltName(critical=critical))
            except:
                pass
            cert.getExtension(SubjectAltName).field['DNS'].\
                append(cert.security.fqdn)

    """
    Get the number of certificates chained in this test case
    (excluding the root CA)
    :returns: integer
    """

    def getDepth(self):
        return len(self.certs)

    """
    Get the first CA (the one immediately signed by the root CA)
    :returns: Certificate object
    """

    def getFirstCA(self):
        return self.certs[0] if self.getDepth() > 1 else None

    """
    Get the second CA (the one immediately signed by the first CA)
    :returns: Certificate object
    """

    def getSecondCA(self):
        return self.certs[1] if self.getDepth() > 2 else None

    """
    Get the leaf CA (the one that directly signs the server certificate)
    :returns: Certificate object
    """

    def getEdgeCA(self):
        return self.certs[-2] if self.getDepth() > 2 else None

    """
    Get the server certificate (the one used in SSL/TLS key agreement)
    :returns: Certificate object
    """

    def getServCert(self):
        return self.certs[-1]

    """
    Get the cipher suite used in this test case
    :returns: string
    """

    def getCipherSuite(self):
        return self.metadata.suite

    """
    Get the SSL/TLS version used in this test case
    :returns: pyOpenSSL macro
    """

    def getSSLVersion(self):
        return self.metadata.sslVer

    """
    Get if the test can form a new chained test case
    :returns: boolean
    """

    def isChainable(self):
        return self.metadata.chainable

    """
    Get if the test can form a new altname test case
    :returns: boolean
    """

    def isAltExtend(self):
        return self.metadata.altextend

    """
    Get if the test case checks functionality instead of certificate validation
    :returns: boolean
    """

    def isFunctional(self):
        return self.metadata.functional

    """
    Get the directory path that holds the test files
    :returns: string
    """

    def getCertDir(self):
        return os.path.join(self.metadata.testDir, self.metadata.name, "")

    """
    Get the file path of the final PEM file to send
    :returns: string
    """

    def getPemPath(self):
        return os.path.join(self.getCertDir(), DEFAULT_PEM_NAME)

    """
    Get the file path of the server certificate keys for the server
    :returns: string
    """

    def getKeyPath(self):
        return os.path.join(self.getCertDir(), DEFAULT_KEY_NAME)

    """
    Get the path prefix of the root CA
    :returns: string
    """

    def getCAPathPrefix(self):
        return self.metadata.caPathPrefix

    """
    Get if the test case is a positive test (a test that is valid)
    :returns: boolean
    """

    def getTestType(self):
        return self.metadata.isValid

    """
    Get if the test case has feature support implication when failed
    :returns: boolean
    """

    def getCritical(self):
        return self.metadata.isCritical

    """
    Get the authentic reference that describe the correct behavior
    :returns: string
    """

    def getReference(self):
        return self.metadata.ref

    """
    Get the name of the test case
    :returns: string
    """

    def getTestName(self):
        return self.metadata.name

    """
    Get the severity if the test case failed
    :returns: Definitions macro
    """

    def getSeverity(self):
        return self.metadata.severity

    """
    Get the ease of execution
    :returns: Definitions macro
    """

    def getEaseOfExec(self):
        return self.metadata.ease

    """
    Prints a message depends on the test case result
    """

    def printMsg(self, passed):
        if (not passed and not self.getCritical()):
            self.info.log("- severity: " + self.getSeverity() + "; ease: "
                          + self.getEaseOfExec() + "; see " +
                          self.getReference())
