"""
This file contains the environment checking, option processing, and test
building logic. The TestSet class builds the list of test cases by
scanning all descendants of TestCase and calling the terminal
descendant's build() method. Some of the user options are passed directly
to the individual test case whereas others are processed locally.


@author: Calvin Jia Liang
Created on Sep 3, 2014
"""

from src.TestCases import *;
from src.TestExpander import *;
from src.TestFunctionality import *;

# TestSet class represents an ordered list of test case OBJECT
# readily available for execution.
class TestSet:

    """
    TestSet constructor
    :param fqdn: fully quantifiable domain name
    :type  fqdn: string
    :param opt: user options
    :type  opt: Terminal object (for now)
    :returns: TestSet object
    """
    def __init__(self, fqdn, opt):
        self.testCases = [];

        self.fqdn = fqdn;
        self.opt  = opt;
        self.info = Information(opt.log, opt.caPathPrefix, opt.testDir,\
                                 opt.caPassword, opt.addr, opt.port, opt.kSize);
        self.exp  = TestExpander(self.fqdn, self.info);

    """
    High level test set build function that determine the flow of the building
    process
    :returns: TestSet object
    """
    def build(self):
        self.opt.log("Checking Root CA...");
        self.checkRootCA();

        self.opt.log("Checking Test Directory...");
        self.initDirectory();

        if (self.opt.compFunc):
            self.opt.log("Building Functionality Test Cases...");
            cases = TestFunctionality(self.fqdn, self.info).build().\
             getTestCases();
            for test in cases:
                self.addTestCase(test, self.opt.replace);

        if (self.opt.compCert):
            self.opt.log("Building X509 Test Cases...");
            cases = self.getAllTestCases(TestCase);
            for test in cases:
                self.addTestCase(test, self.opt.replace);

        self.baseCase = ValidCert(self.fqdn, self.info);
        self.baseCase.testBuild(False);

        saveSerial();

        return self;

    @staticmethod
    def getAllNames(exclude):
        return TestSet.getDescNames({}, TestCase, exclude);

    @staticmethod
    def getDescNames(arr, root, exclude):
        for c in root.__subclasses__():
            if (c.__name__ in exclude):
                for b in TestSet.getBaseNames({}, c):
                    if (b.__name__ in arr):
                        del arr[b.__name__];
            else:
                arr[c.__name__] = c.__name__;
                if (len(c.__subclasses__()) > 0):
                    TestSet.getDescNames(arr, c, exclude);

        return arr;

    @staticmethod
    def getBaseNames(arr, base):
        if (base != TestCase):
            arr[base] = base;
            TestSet.getBaseNames(arr, base.__bases__[0]);

        return arr;

    def getTestSet(self):
        return self.testCases;

    """
    Initialize the test directory if non existed, or remove all contents in the
    directory if 'replace' is asserted
    """
    def initDirectory(self):
        if (not os.path.exists(self.info.testDir)):
            os.mkdir(self.info.testDir);
        if (self.opt.replace):
            if (len(os.listdir(self.info.testDir)) != 0 and\
                not os.path.exists(os.path.join(self.info.testDir,\
                                                ValidCert.__name__))):
                raise Exception("Please manually remove items in directory %s"\
                                % (self.info.testDir));
            shutil.rmtree(self.info.testDir);
            os.mkdir(self.info.testDir);
            os.remove(DEFAULT_SERIAL_PATH);
        with open(DEFAULT_SERIAL_PATH, 'w+') as f:
            f.write(str(DEFAULT_SERIAL));

    """
    Make sure that the KEY, CRT, and PEM file of the root CA exists
    """
    def checkRootCA(self):
        keyFile = self.info.caPathPrefix+".key";
        crtFile = self.info.caPathPrefix+".crt";
        pemFile = self.info.caPathPrefix+".pem";
        dirName = os.path.dirname(self.info.caPathPrefix);

        if (not os.path.exists(dirName)):
            os.mkdir(dirName);

        if (not os.path.isfile(keyFile) and not os.path.isfile(crtFile)):
            security = CertSec(DEFAULT_CA_NAME);
            subject  = CertSubj(security.fqdn);
            signer   = CertSign(None, security.certKey, subject.getSubject());
            cert     = Certificate(self.info.caPathPrefix, signer, security);

            cert.addExtension(BasicConstraint(True));

            cert.security.build();
            cert.signer.build();
            cert.build();
            cert.writeKey(keyPassword=self.info.caPassword);
        elif (not os.path.isfile(keyFile) or not os.path.isfile(crtFile)):
            raise Exception("Missing %s or %s" % (keyFile, crtFile));

        if (not os.path.isfile(pemFile)):
            shutil.copy(crtFile, pemFile);

    """
    Print and count all test cases in a hierarchical format recursively
    :param root: the root of the test hierarchy
    :type  root: TestCase Class object
    :param prepend: visual cue prepended before the name of the test case
    :type  prepend: string
    :returns: integer
    """
    def printAllTestCases(self, root, prepend):
        cnt = 0;
        for c in root.__subclasses__():
            if (self.isExcluded(c)):
                continue;

            if (len(c.__subclasses__()) > 0):
                self.opt.log(prepend + "> " + c.__name__);
                cnt += self.printAllTestCases(c, prepend+"  ");
            else:
                case = c("get.metadata.only", self.info);
                if (case.isChainable() or case.isAltExtend()):
                    self.opt.log(prepend + "+ " + case.getTestName());
                    if (case.isChainable()):
                        self.opt.log(prepend + "  " +\
                                     getChainedName(case.getTestName()));
                        cnt += 1;
                    if (case.isAltExtend()):
                        self.opt.log(prepend + "  " +\
                                     getAltExtendedName(case.getTestName()));
                        cnt += 1;
                else:
                    self.opt.log(prepend + "- " + case.getTestName());
                cnt += 1;
        return cnt;

    """
    Check if the test case is excluded from execution
    :param case: the test case in question
    :type  case: TestCase object or TestCase Class object
    :returns: boolean
    """
    def isExcluded(self, case):
        c = case;
        if (not hasattr(c, '__name__')):
            c = c.__class__;

        while (True):
            name = c.__name__;

            if (name == TestCase.__name__):
                break;
            if (name in self.opt.exclude):
                return True;

            c = c.__bases__[0];


        return False;

    """
    Get the most basic positive test case that all compliance entity should pass
    :returns: TestCase object
    """
    def getBaseCase(self):
        return self.baseCase;

    """
    Insert test cases into an ordered list where the order is based on the 
    following rules:
    1. critical test cases have highest priority
    2. test cases closer to the root have higher priority
    3. test cases/groups appears first in the file have higher priority
    4. test cases more severe when failed have higher priority
    :returns: list of TestCase object
    """
    def getAllTestCases(self, root):
        cases = [];
        counter = 0;
        q = queue.PriorityQueue();

        q.put((0, counter, root));
        while (not q.empty()):
            c = q.get()[2];

            if (self.isExcluded(c)):
                continue;
            if (not hasattr(c, '__subclasses__')):
                cases.append(c);
            else:
                for r in c.__subclasses__():
                    expansions = [];
                    s = 0;

                    counter += 1;
                    if (self.exp.isExpansion(r)):
                        continue;
                    if (len(r.__subclasses__()) != 0):
                        s += 100000;
                    else:
                        rc = r;
                        r = rc(self.fqdn, self.info);
                        if (not r.getCritical()):
                            if (r.getSeverity() == SEV_HIGH):
                                s += 100;
                            elif (r.getSeverity() == SEV_MED):
                                s += 200;
                            else:
                                s += 300;
                        s += len(rc.__bases__);

                        expansions = self.exp.getExpansions(r);

                    q.put((s, counter, r));
                    for e in expansions:
                        s += 1;
                        q.put((s, counter, e));


        counter = 0;
        for c in cases:
            s = 1;
            counter += 1;
            if (c.getCritical()):
                s = 0;
            q.put((s, counter, c));

        cases = [];
        while (not q.empty()):
            cases.append(q.get()[2]);


        return cases;

    def addTestCase(self, testCase, replace = False):
        if (VERBOSE):
            self.opt.log("adding " + str(testCase.getTestName()));
        testCase.testBuild(replace);
        self.testCases.append(testCase);
