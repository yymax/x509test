"""
This file contains the automatic test generation logic that generates VALID
and POSITIVE test cases under different configuration. It is used to test
the different handshake settings in which the other end is willing to accept.

NOTE: Even the test cases generated is valid on paper, it is still critical
      for the other end to reject some of its test cases. Settings like
      anonymous Diffie-Hellman should never be accepted by any secure
      entity.

@author: Calvin Jia Liang
Created on Sep 7, 2014
"""

from src.TestGroups import *


class TestFunctionality:

    """
    TestFunctionality constructor
    :param fqdn: fully quantifiable domain name
    :type  fqdn: string
    :param info: other information for the test session
    :type  info: Information object
    :param sizes: key lengths to test
    :type  sizes: list of integer
    :param types: type of certificates to test
    :type  types: list of pyOpenSSL macro
    :param suites: cipher suites to test
    :type  suites: list of string
    :param versions: type of SSL/TLS versions to test
    :type  versions: list of pyOpenSSL macro
    :returns: TestFunctionality object
    """

    def __init__(self, fqdn, info):
        self.fqdn = fqdn
        self.info = copy.copy(info)
        self.info.metadata = None

        self.sizes = FUNC_KEY_SIZES
        self.types = FUNC_KEY_TYPES
        self.hashes = FUNC_HASH_TYPES
        self.suites = FUNC_CIPHER_SUITES
        self.versions = FUNC_SSL_VERSIONS
        self.cases = []

    """
    Build a list of functionality test cases based on the input given; they are
    positive test cases that only differ in one or two components
    :returns: TestFunctionality object
    """

    def build(self):
        metadata = TestMetadata("", "", None, None, False, True,
                                functional=True)

        for ktype in self.types:
            for size in self.sizes:
                mdata = copy.copy(metadata)
                mdata.name = self.getKeyName(ktype, size)
                mdata.suite = "ALL"

                case = TestCase(self.fqdn, mdata, self.info)
                case.getServCert().security.certKey = CertKey(None, kSize=size,
                                                              kType=ktype)

                self.cases.append(case)

        for version in self.versions:
            for suite in self.suites:
                mdata = copy.copy(metadata)
                mdata.name = self.getSuiteName(version, suite)
                mdata.sslVer = version
                mdata.suite = suite

                case = TestCase(self.fqdn, mdata, self.info)
                self.cases.append(case)

        for version in self.versions:
            for digest in self.hashes:
                mdata = copy.copy(metadata)
                mdata.name = self.getHashName(version, digest)
                mdata.sslVer = version
                mdata.suite = "ALL"

                case = TestCase(self.fqdn, mdata, self.info)
                case.getServCert().security.digest = digest

                self.cases.append(case)

        return self

    def getKeyName(self, ktype, size):
        name = ""

        if (ktype == crypto.TYPE_RSA):
            name += "RSA"
        elif (ktype == crypto.TYPE_DSA):
            name += "DSA"
        else:
            forcedExit("Unknown Key Type.", self.log)
        name += "_" + str(size)

        return name

    def getHashName(self, version, digest):
        return self.getVersionName(version) + '_' + digest

    def getSuiteName(self, version, suite):
        return self.getVersionName(version) + '_' + suite

    def getVersionName(self, sver):
        ver = None

        if (sver == SSL.SSLv23_METHOD):
            ver = "SSLv23"
        elif (sver == SSL.SSLv2_METHOD):
            ver = "SSLv2"
        elif (sver == SSL.SSLv3_METHOD):
            ver = "SSLv3"
        elif (sver == SSL.TLSv1_METHOD):
            ver = "TLSv1_0"
        elif (sver == SSL.TLSv1_1_METHOD):
            ver = "TLSv1_1"
        elif (sver == SSL.TLSv1_2_METHOD):
            ver = "TLSv1_2"
        else:
            forcedExit("Unknown SSL/TLS Version.", self.info.log)

        return ver

    def getAllNames(self, tbl, exclude):
        for ktype in self.types:
            for size in self.sizes:
                name = self.getKeyName(ktype, size)
                if (name not in exclude):
                    tbl[name] = name

        for version in self.versions:
            for suite in self.suites:
                name = self.getSuiteName(version, suite)
                if (name not in exclude):
                    tbl[name] = name

        for version in self.versions:
            for digest in self.hashes:
                name = self.getHashName(version, digest)
                if (name not in exclude):
                    tbl[name] = name

        return tbl

    """
    Get the list of test cases created from this object
    :returns: list of TestCase object
    """

    def getTestCases(self):
        return self.cases
