"""
This file contains all generation logic and data structure relating to the
X509 certificate. Class Certificate represents a single certificate. Other
peripheral classes supply information to the Certificate object.

@author: Calvin Jia Liang
Created on May 15, 2014
"""

from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459

from src.Definitions import *

# Certificate subject class that represents the subject distinguish name.


class CertSubj:

    """
    CertSubj constructor
    :param commonName: common name (CN)
    :type  commonName: string
    :param country: country (C)
    :type  country: string
    :param state: state (ST)
    :type  state: string
    :param city: location (L)
    :type  city: string
    :param org: organization (O)
    :type  org: string
    :param unit: unit (U)
    :type  unit: string
    :param email: email
    :type  email: string
    :returns: CertSubj object
    """

    def __init__(self, commonName, country=DEFAULT_C, state=DEFAULT_ST,
                 city=DEFAULT_L, org=DEFAULT_O, unit=DEFAULT_U,
                 email=DEFAULT_EMAIL):

        self.commonName = commonName
        self.country = country
        self.state = state
        self.city = city
        self.org = org
        self.unit = unit
        self.email = email

    """
    Build all missing, or computationally expensive, components in this object
    :returns: CertSubj object
    """

    def build(self):
        return self

    """
    Get information in this object in pyOpenSSL format
    :returns: pyOpenSSL Subject object
    """

    def getSubject(self):
        subj = crypto.X509().get_subject()
        subj.C = self.country
        subj.ST = self.state
        subj.L = self.city
        subj.O = self.org
        subj.OU = self.unit
        subj.CN = self.commonName
        subj.emailAddress = self.email

        return subj

# Certificate key class that represents the public/private key pair.


class CertKey:

    """
    CertSubj constructor
    :param key: public/private key pairs
    :type  key: pyOpenSSL key object
    :param kSize: length of the key
    :type  kSize: integer
    :param kType: type of the key
    :type  kType: pyOpenSSL macro
    :returns: CertKey object
    """

    def __init__(self, key=None, kSize=DEFAULT_KSIZE, kType=DEFAULT_KTYPE):
        self.key = key
        self.kSize = kSize
        self.kType = kType

    """
    Build all missing, or computationally expensive, components in this object
    :returns: CertKey object
    """

    def build(self):
        if (not self.key):
            self.key = crypto.PKey()
            self.key.generate_key(self.kType, self.kSize)

        return self

# Certificate security class that holds the subject public key and
# other miscellaneous information.


class CertSec:

    """
    CertSec constructor
    :param fqdn: fully quantifiable domain name
    :type  fqdn: string
    :param notBefore: hours (absolute value) before NOW when the validity begins
    :type  notBefore: integer
    :param notAfter: hours (absolute value) after NOW when the validity ends
    :type  notAfter: integer
    :param key: key of this certificate
    :type  key: CertKey object
    :param kSize: length of the key
    :type  kSize: integer
    :param kType: type of the key
    :type  kType: pyOpenSSL macro
    :param version: X509 certificate version
    :type  version: pyOpenSSL macro
    :param digest: type of the hash algorithm
    :type  digest: string
    :param serial: serial number of the certificate
    :type  serial: integer
    :returns: CertSec object
    """

    def __init__(
            self, fqdn, notBefore=DEFAULT_HOUR_BEFORE,
            notAfter=DEFAULT_HOUR_AFTER, key=None, kSize=DEFAULT_KSIZE,
            kType=DEFAULT_KTYPE, version=DEFAULT_VERSION,
            digest=DEFAULT_DIGEST, serial=None):

        self.fqdn = fqdn
        self.digest = digest
        self.serial = serial
        self.version = version
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.serial = serial if serial else getNewSerial()
        self.certKey = CertKey(key, kSize, kType)

    """
    Get the actual keys used in the certificate
    :returns: pyOpenSSL Key object
    """

    def getKey(self):
        return self.certKey.key

    """
    Build all missing, or computationally expensive, components in this object
    :returns: CertSec object
    """

    def build(self):
        self.certKey.build()
        return self

# Certificate signer class that holds the signer's information.


class CertSign:

    """
    CertSign constructor
    :param signPathPrefix: path prefix of the signer's cert and key files in PEM
    :type  signPathPrefix: string
    :param signKey: private key of the signer
    :type  signKey: pyOpenSSL pkey object
    :param signSubj: distinguish name of the signer
    :type  signSubj: pyOpenSSL subject object
    :param keyPassword: password of the key file (only used when signKey==None)
    :type  keyPassword: string
    :returns: CertSign object
    """

    def __init__(
            self, signPathPrefix, signKey=None, signSubj=None,
            keyPassword=DEFAULT_PASSWORD):
        self.signPathPrefix = signPathPrefix
        self.signKey = signKey
        self.signSubj = signSubj

        self.keyPassword = keyPassword.encode('utf-8')

    """
    Get the actual keys used for signature
    :returns: pyOpenSSL Key object
    """

    def getKey(self):
        return self.signKey.key

    """
    Build all missing, or computationally expensive, components in this object
    :returns: CertSign object
    """

    def build(self):
        if (not self.signKey):
            keyPath = self.signPathPrefix + ".key"
            with open(keyPath, 'rb') as f:
                key = crypto.load_privatekey(
                    crypto.FILETYPE_PEM,
                    f.read(),
                    self.keyPassword)
                self.signKey = CertKey(key, None, None)

        if (not self.signSubj):
            crtPath = self.signPathPrefix + ".crt"
            with open(crtPath, 'rb') as f:
                self.signSubj = crypto.load_certificate(
                    crypto.FILETYPE_PEM,
                    f.read()).get_subject()

        return self

# Abstract class that represents a generic certificate extension type.


class CertExt:

    """
    CertExt constructor
    :param critical: assert if the extension is critical
    :type  critical: boolean
    :returns: CertExt object
    """

    def __init__(self, critical=False):
        self.critical = critical

    """
    Check if the extension is critical
    :returns: boolean
    """

    def criticality(self):
        return self.critical

    """
    Get the name of this extension in pyOpenSSL format
    :returns: bytes
    """

    def name(self):
        pass

    """
    Get the value of this extension in pyOpenSSL format
    :returns: bytes
    """

    def value(self):
        pass

# Basic constraint class that represents the RFC5280 4.2.1.9 extension.


class BasicConstraint(CertExt):

    """
    BasicConstraint constructor
    :param ca: assert if the certificate represents a CA
    :type  ca: boolean
    :param pathLen: the maximum depth in which the CA is able to sign descendant CA
    :type  pathLen: string
    :param critical: assert if the extension is critical
    :type  critical: boolean
    :returns: BasicConstraint object
    """

    def __init__(self, ca, pathLen=None, critical=True):
        super(self.__class__, self).__init__(critical)
        self.ca = ca
        self.pathLen = pathLen

    """
    See CertExt
    """

    def name(self):
        return b"basicConstraints"

    """
    See CertExt
    """

    def value(self):
        val = b"CA:" + (b"TRUE" if self.ca else b"FALSE")

        if (self.pathLen is not None):
            val += b",pathlen:" + str(self.pathLen).encode("utf-8")

        return val

# Key usage class that represents the RFC5280 4.2.1.3 extension.


class KeyUsage(CertExt):

    """
    KeyUsage constructor
    :param digitalSignature: assert if digitalSignature
    :type  digitalSignature: boolean
    :param contentCommitment: assert if contentCommitment
    :type  contentCommitment: boolean
    :param keyEncipherment: assert if keyEncipherment
    :type  keyEncipherment: boolean
    :param keyAgreement: assert if keyAgreement
    :type  keyAgreement: boolean
    :param keyCertSign: assert if keyCertSign
    :type  keyCertSign: boolean
    :param cRLSign: assert if cRLSign
    :type  cRLSign: boolean
    :param encipherOnly: assert if encipherOnly
    :type  encipherOnly: boolean
    :param decipherOnly: assert if decipherOnly
    :type  decipherOnly: boolean
    :param critical: assert if critical
    :type  critical: boolean
    :returns: KeyUsage object
    """

    def __init__(
            self, digitalSignature=False, contentCommitment=False,
            keyEncipherment=False, dataEncipherment=False, keyAgreement=False,
            keyCertSign=False, cRLSign=False, encipherOnly=False,
            decipherOnly=False, critical=True):
        super(self.__class__, self).__init__(critical)

        self.field = {}
        self.field['digitalSignature'] = digitalSignature
        self.field['nonRepudiation'] = contentCommitment
        self.field['keyEncipherment'] = keyEncipherment
        self.field['dataEncipherment'] = dataEncipherment
        self.field['keyAgreement'] = keyAgreement
        self.field['keyCertSign'] = keyCertSign
        self.field['cRLSign'] = cRLSign
        self.field['encipherOnly'] = encipherOnly
        self.field['decipherOnly'] = decipherOnly

    def name(self):
        return b"keyUsage"

    def value(self):
        val = b""
        for k in self.field.keys():
            if (self.field[k]):
                val += (b"" if val == b"" else b",") + k.encode('utf-8')

        return val

# Extended key usage class that represents the RFC5280 4.2.1.12 extension.


class ExtendedKeyUsage(CertExt):

    """
    ExtendedKeyUsage constructor
    :param serverAuth: assert if serverAuth
    :type  serverAuth: boolean
    :param clientAuth: assert if clientAuth
    :type  clientAuth: boolean
    :param emailProtection: assert if emailProtection
    :type  emailProtection: boolean
    :param timeStamping: assert if timeStamping
    :type  timeStamping: boolean
    :param OCSPSigning: assert if OCSPSigning
    :type  OCSPSigning: boolean
    :param critical: assert if critical
    :type  critical: boolean
    :returns: ExtendedKeyUsage object
    """

    def __init__(self, serverAuth=False, clientAuth=False, codeSigning=False,
                 emailProtection=False, timeStamping=False, OCSPSigning=False,
                 critical=True):
        super(self.__class__, self).__init__(critical)

        self.field = {}
        self.field['serverAuth'] = serverAuth
        self.field['clientAuth'] = clientAuth
        self.field['codeSigning'] = codeSigning
        self.field['emailProtection'] = emailProtection
        self.field['timeStamping'] = timeStamping
        self.field['OCSPSigning'] = OCSPSigning

    def name(self):
        return b"extendedKeyUsage"

    def value(self):
        val = b""
        for k in self.field.keys():
            if (self.field[k]):
                val += (b"" if val == b"" else b",") + k.encode('utf-8')

        return val

# Subject alternative name class that represents the RFC5280 4.2.1.6 extension.


class SubjectAltName(CertExt):

    """
    SubjectAltName constructor
    :param dnsID: list of DNS-ID
    :type  dnsID: list of string
    :param addrID: list of ADDR-ID
    :type  addrID: list of string
    :param uriID: list of URI-ID
    :type  uriID: list of string
    :param srvID: list of SRV-ID
    :type  srvID: list of string
    :param critical: assert if critical
    :type  critical: boolean
    :returns: SubjectAltName object
    """

    def __init__(
            self, dnsID=None, addrID=None, uriID=None, srvID=None,
            critical=True):
        super(self.__class__, self).__init__(critical)

        self.field = {}
        self.field['DNS'] = dnsID if dnsID else []
        self.field['IP'] = addrID if addrID else []
        self.field['URI'] = uriID if uriID else []
        self.field['SRV'] = srvID if srvID else []

    def name(self):
        return b"subjectAltName"

    def value(self):
        val = b""

        for k in self.field.keys():
            ln = b""
            dim = b""
            if (len(self.field[k])):
                ln += k.encode('utf-8') + b":"
                for v in self.field[k]:
                    ln += dim + v.encode('utf-8')
                    dim = b","
                val += (b"" if val == b"" else b",") + ln

        return val

# Name constraints class that represents the RFC5280 4.2.1.10 extension.


class NameConstraints(CertExt):

    """
    NameConstraints constructor
    :param permit: list of permitted DNS-ID
    :type  permit: list of string
    :param exclude: list of excluded DNS-ID
    :type  exclude: list of string
    :param critical: assert if critical
    :type  critical: boolean
    :returns: NameConstraints object
    """

    def __init__(self, permit=None, exclude=None, critical=True):
        super(self.__class__, self).__init__(critical)

        self.field = {}
        self.field['permitted'] = permit if permit else []
        self.field['excluded'] = exclude if exclude else []

    def name(self):
        return b"nameConstraints"

    def value(self):
        val = b""

        for k in self.field.keys():
            ln = b""
            dim = b""
            if (len(self.field[k])):
                ln += k.encode('utf-8') + b";DNS:"
                for v in self.field[k]:
                    ln += dim + v.encode('utf-8')
                    dim = b"," + k.encode('utf-8') + b";DNS:"
                val += (b"" if val == b"" else b",") + ln

        return val

# Certificate modifier class that holds callback functions that alter the behavior
# of the certificate generation logic at different stages


class CertMod:

    """
    CertMod constructor
    :param hasPreSign: assert if preSign() is overridden
    :type  hasPreSign: boolean
    :param hasPostSign: assert if postSign() is overridden
    :type  hasPostSign: boolean
    :param hasPostWrite: assert if postWrite() is overridden
    :type  hasPostWrite: boolean
    :returns: CertMod object
    """

    def __init__(self, hasPreSign=False, hasPostSign=False,
                 hasPostWrite=False):
        self.hasPreSign = hasPreSign
        self.hasPostSign = hasPostSign
        self.hasPostWrite = hasPostWrite

    """
    Callback function to be overridden; call immediately before signature process
    :param asnObj: certificate to be altered in asn1 format
    :type  asnObj: pyasn1 object
    :returns: pyasn1 object
    """

    def preSign(self, asnObj):
        return asnObj

    """
    Callback function to be overridden; call immediately after signature process
    :param asnObj: certificate to be altered in asn1 format
    :type  asnObj: pyasn1 object
    :returns: pyasn1 object
    """

    def postSign(self, asnObj):
        return asnObj

    """
    Callback function to be overridden; call immediately after write process
    :param cert: certificate to be altered
    :type  cert: Certificate object
    :param certPathPrefix: location of the certificate in hard disk
    :type  certPathPrefix: string
    :returns: pyasn1 object
    """

    def postWrite(self, cert, certPathPrefix):
        return None

# Certificate class that represents a X509 certificate


class Certificate:

    """
    Certificate constructor
    :param certPathPrefix: path prefix of the certificate (destination location)
    :type  certPathPrefix: string
    :param signer: signer information
    :type  signer: CertSign object
    :param security: security information
    :type  security: CertSec object
    :param extensions: certificate extensions
    :type  extensions: list of CertExt
    :param subject: distinguish name
    :type  subject: CertSubj object
    :param modifier: certificate modifiers
    :type  modifier: CertMod object
    :returns: Certificate object
    """

    def __init__(
            self, certPathPrefix, signer, security, extensions=None,
            subject=None, modifier=None):

        self.certPathPrefix = certPathPrefix
        self.signer = signer
        self.security = security
        self.extensions = extensions if extensions else []
        self.subject = subject if subject else CertSubj(security.fqdn)
        self.modifier = modifier if modifier else CertMod()

    """
    Build the certificate and write it to hard disk
    :param chainCerts: assert if cert is included in the final PEM file
    :type  chainCerts: boolean
    :returns: pyOpenSSL Certificate object
    """

    def build(self, chainCerts=True):
        crtPath = self.certPathPrefix + ".crt"
        pemPath = os.path.join(
            os.path.dirname(
                self.certPathPrefix),
            DEFAULT_PEM_NAME)

        cert = crypto.X509()
        cert.set_version(self.security.version)
        cert.set_serial_number(self.security.serial)
        cert.gmtime_adj_notBefore(self.security.notBefore * 3600)
        cert.gmtime_adj_notAfter(self.security.notAfter * 3600)
        cert.set_subject(self.subject.getSubject())
        cert.set_issuer(self.signer.signSubj)
        cert.set_pubkey(self.security.getKey())

        extList = []
        for ext in self.extensions:
            extList.append(
                crypto.X509ExtensionType(
                    ext.name(),
                    ext.criticality(),
                    ext.value()))
        cert.add_extensions(extList)

        if (self.modifier.hasPreSign):
            cert = self.asnModify(cert, self.modifier.preSign)
        cert.sign(self.signer.getKey(), self.security.digest)
        if (self.modifier.hasPostSign):
            cert = self.asnModify(cert, self.modifier.postSign)

        with open(crtPath, 'wb+') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        if (self.modifier.hasPostWrite):
            self.modifier.postWrite(self.modifier, self.certPathPrefix)

        if (chainCerts):
            if (not os.path.exists(pemPath)):
                with open(pemPath, 'wb+') as f:
                    if (self.signer.signPathPrefix):
                        rootPem = self.signer.signPathPrefix + ".pem"
                        if (os.path.exists(rootPem)):
                            with open(rootPem, "rb") as r:
                                f.write(r.read())
            concatFiles(crtPath, pemPath, pemPath)

        self.cert = cert
        return cert

    """
    Get this certificate
    :returns: pyOpenSSL Certificate object
    """

    def getCert(self):
        return self.cert

    """
    Indicate a self-signed certificate
    """
    def selfSign(self):
        self.security.certKey.build()
        self.signer = CertSign(
                None,
                self.security.certKey,
                self.subject.getSubject())

    """
    Add an extension entry to this certificate
    :param extension: extension to be added to the certificate
    :type  extension: CertExt object
    :returns: CertExt object
    """

    def addExtension(self, extension):
        if (self.getExtension(extension.__class__)):
            raise Exception(
                "The extension type %s already exists" %
                extension.__class__.__name__)

        self.extensions.append(extension)

        return extension

    """
    Get an extension entry, with specified type, from this certificate
    :param extendType: extension type
    :type  extendType: CertExt Class object
    :returns: CertExt object; None if no matching type if found
    """

    def getExtension(self, extendType):
        for e in self.extensions:
            if (e.__class__ == extendType):
                return e

        return None

    """
    Remove an extension entry, with specified type, from this certificate
    :param extendType: extension type
    :type  extendType: CertExt Class object
    :returns: CertExt object; None if no matching type if found
    """

    def removeExtension(self, extendType):
        rtn = None
        i = 0

        for e in self.extensions:
            if (e.__class__ == extendType):
                rtn = e
                del self.extensions[i]
                break
            i += 1

        return rtn

    """
    Writes the key pairs used in this certificate to file
    :param path: destination of the file in the file system
    :type  path: string
    :param keyPassword: pass phrase for the file
    :type  keyPassword: string
    :returns: string
    """

    def writeKey(self, path=None, keyPassword=None):
        keyPath = path if path else self.certPathPrefix + ".key"

        with open(keyPath, 'wb+') as f:
            if (keyPassword):
                f.write(
                    crypto.dump_privatekey(
                        crypto.FILETYPE_PEM,
                        self.security.getKey(),
                        DEFAULT_CIPHER,
                        keyPassword.encode('utf-8')))

            else:
                f.write(
                    crypto.dump_privatekey(
                        crypto.FILETYPE_PEM,
                        self.security.getKey()))

        return keyPath

    """
    Transform a x509 object to asn1 object, call the callback function
    to with the asn1 object, and transform the result back to x509
    :param cert: x509 certificate
    :type  cert: pyOpenSSL Certificate object
    :param func: callback function that transform the certificate
    :type  func: Function object
    :returns: pyOpenSSL Certificate object
    """

    def asnModify(self, cert, func):
        substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]

        cert = func(cert)

        substrate = encoder.encode(cert)
        return crypto.load_certificate(crypto.FILETYPE_ASN1, substrate)
