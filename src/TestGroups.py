"""
This file holds all (abstract) classes that are descendant of TestCase.
They are the intermediate nodes in the test case inheritance hierarchy.
They help to organize test cases into different groups for better management.
Some provide additional functionalities for their descendants.

@author: Calvin Jia Liang
Created on Sep 3, 2014
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


from src.Test import *;


# Immediate test case group where a basic server certificate is directly  
# signed by the root certificate.
# The server certificate is the test certificate.
class TestCaseImmed(TestCase):
    pass;

# Chained test case group where a basic server certificate is signed by an  
# intermediate CA, which ultimately linked to the root certificate (if signed
# correctly).
# The intermediate CAs (usually the one directly signed by the root CA) 
# is the test certificate.
class TestCaseChained(TestCase):
    def __init__(self, fqdn, metadata, info, depth=DEFAULT_NUM_CHAINED):
        self.newTestCaseChained(fqdn, metadata, info, depth);

    def newTestCaseChained(self, fqdn, metadata, info, depth):
        super(TestCaseChained, self).__init__(fqdn, metadata, info, depth);
        return self;

# Wildcard test case group where a server certificate uses wildcard characters
# to identify itself.
# The server certificate is the test certificate.
class TestCaseWildcard(TestCase):
    pass;

# AltName test case group where some certificates contains the Alternative Name
# Extension.
# It will render the CN of the server certificate incorrectly by default. 
class TestCaseAltName(TestCase):
    def __init__(self, fqdn, metadata, info):
        self.newTestCaseAltName(fqdn, metadata, info);

    def newTestCaseAltName(self, fqdn, metadata, info):
        super(TestCaseAltName, self).__init__(fqdn, metadata, info);

        self.includeAltName();
        self.getServCert().subject.commonName = getInvalidDomain(fqdn);

        return self;

# Chained test case group where some intermediate CA certificates contains 
# the Name Constraint Extension.
# All certificates contains AltName extension by default.
class TestCaseNameConstraint(TestCaseChained):
    def __init__(self, fqdn, metadata, info):
        self.newTestCaseNameConstraint(fqdn, metadata, info);

    def newTestCaseNameConstraint(self, fqdn, metadata, info):
        super(TestCaseNameConstraint, self).__init__(fqdn, metadata, info);

        self.includeAltName(critical=False);
        self.appendPermit(self.getFirstCA(), getIntCADomain());

        return self;

    def appendConstraint(self, cert, ln, k):
        ext = cert.getExtension(NameConstraints);
        ext = ext if ext else cert.addExtension(NameConstraints());
        ext.field[k].append(ln);

    def appendPermit(self, cert, ln):
        self.appendConstraint(cert, ln, 'permitted');

    def appendExclude(self, cert, ln):
        self.appendConstraint(cert, ln, 'excluded');
