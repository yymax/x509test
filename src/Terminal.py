"""
This file holds the Terminal class that parse user input and process
system output. It mainly parse the options given by the user from the
runtime argument to a internal data structure.

@author: Calvin Jia Liang
Created on Sep 3, 2014
"""

from src.TestServer import *
from optparse import OptionParser

# Terminal class that handles all terminal I/O.


class Terminal:

    def __init__(self):
        pass

    def usage(self):
        return "usage: " + sys.argv[0] + " fqdn [options]"

    """
    Build the option attributes from user arguments
    :returns: string, parser Option object
    """

    def build(self):
        parser = OptionParser(usage=self.usage())
#         parser.add_option("-n", "--fqdn", dest="fqdn", default=None, \
#                        help="fully-qualified-domain-name of your domain");
        parser.add_option("-a", "--address", dest="addr",
                          default=DEFAULT_ADDR,
                          help="IP address of your domain")
        parser.add_option("", "--service", dest="serv",
                          help="service offered by your domain")
        parser.add_option("", "--ssl", dest="sver",
                          help="ssl/tls version; possible values are SSLv2," +
                          " SSLv3, [SSLv23], TLSv1_0, TLSv1_1, TLSv1_2")
        parser.add_option("", "--exclude-all", dest="exclude",
                          help="exclude all specified test groups/cases;" +
                          " comma separated name-list without spaces")
        parser.add_option("", "--include-only", dest="include",
                          help="include only specified test groups/cases;" +
                          " comma separated name-list without spaces")
        parser.add_option("-c", "--component", dest="comp",
                          help="specify components to run;" +
                          " possible values are full, func, [cert], overflow")

        parser.add_option("-p", "--port", dest="port",
                          type="int", default=DEFAULT_PORT,
                          help="port number of the server")
        parser.add_option("", "--key-length", dest="kSize",
                          type="int", default=DEFAULT_KSIZE,
                          help="key length for all certificates")
        parser.add_option("", "--overflow-length", dest="overflowLen",
                          type="int", default=DEFAULT_OVERFLOW_LENGTH,
                          help="byte length of the overflow filler")
        parser.add_option("", "--pause", dest="pause",
                          type="int", default=DEFAULT_PAUSE,
                          help="number of seconds between each test case")
        
        parser.add_option("-r", "--replace", action="store_true",
                          dest="replace", default=False,
                          help="rebuild all test certificates (NOTE: this" +
                          " option will REMOVE ALL ITEMS under path" +
                          " configured by --test-dir)")
        parser.add_option("", "--all", action="store_true",
                          dest="all", default=False,
                          help="include all test cases; " +
                          "disregard results from compatibility test")
        parser.add_option("", "--diligent", action="store_true",
                          dest="diligent", default=False,
                          help="every test case is repeated three times " +
                          "followed by a valid base case")
        parser.add_option("-q", "--quiet", action="store_true",
                          dest="quiet", default=False,
                          help="show only failed test cases")
        parser.add_option("-l", "--list", action="store_true",
                          dest="list", default=False,
                          help="list all test cases then exit")
        parser.add_option("", "--cert-only", action="store_true",
                          dest="conly", default=False,
                          help="generate all test cases then exit")
        parser.add_option("", "--version", action="store_true",
                          dest="pver", default=False,
                          help="print version information then exit")

        parser.add_option("", "--ca-prefix", dest="caPathPrefix",
                          default=DEFAULT_CA_PREFIX,
                          help="set root ca path prefix (ie. /certs/ca)")
        parser.add_option("", "--test-dir", dest="testDir",
                          default=DEFAULT_CERT_DIR,
                          help="set directory path for test cases (NOTE: " +
                          "setting this path incorrectly may result in lost " +
                          "of data; thus, it is recommended to not use this " +
                          "option if possible)")
        parser.add_option("", "--ca-password", dest="caPassword",
                          default=DEFAULT_PASSWORD,
                          help="specify password for CA private key")
        parser.add_option("-w", "--write", dest="logPath",
                          default=None, help="set path for output file")

        (opt, args) = parser.parse_args(sys.argv)

        self.logStream = self.getLogStream(opt.logPath)
        self.addr = opt.addr
        self.port = opt.port
        self.kSize = opt.kSize
        self.overflowLen = opt.overflowLen
        self.pause = opt.pause
        self.serv = opt.serv
        self.sslVer = self.getSSLVer(opt.sver)
        self.exclude = self.getExclude(opt.exclude, opt.include)
        self.replace = opt.replace and not opt.list
        self.all = opt.all
        self.diligent = opt.diligent
        self.quiet = opt.quiet
        self.list = opt.list
        self.caPathPrefix = opt.caPathPrefix
        self.testDir = opt.testDir
        self.caPassword = opt.caPassword
        self.compCert, self.compFunc, self.compOverflow = self.getComp(opt.comp)
        self.conly = opt.conly
        self.pver = opt.pver

        if (len(args) != 2):
            forcedExit(self.usage(), self.log)
        return args[1], opt

    def getExclude(self, exclude, include):
        ls = {}

        if (include):
            ls = TestSet.getAllNames(include.split(','))
        if (exclude):
            for e in exclude.split(','):
                ls[e] = e

        return ls

    def getSSLVer(self, sver):
        ver = None

        if (sver is None):
            ver = SSL.SSLv23_METHOD
        elif (sver == "SSLv2"):
            ver = SSL.SSLv2_METHOD
        elif (sver == "SSLv3"):
            ver = SSL.SSLv3_METHOD
        elif (sver == "SSLv23"):
            ver = SSL.SSLv23_METHOD
        elif (sver == "TLSv1_0"):
            ver = SSL.TLSv1_METHOD
        elif (sver == "TLSv1_1"):
            ver = SSL.TLSv1_1_METHOD
        elif (sver == "TLSv1_2"):
            ver = SSL.TLSv1_2_METHOD
        else:
            forcedExit("Unknown SSL/TLS Version.", self.log)

        return ver

    def getLogStream(self, path):
        stream = sys.stdout

        if (path):
            if (path == '-'):
                pass
            elif (path == '+'):
                stream = sys.stderr
            else:
                stream = open(path, "w+")
        return stream

    def getComp(self, comp):
        compCert = compFunc = compOverflow = False

        if (not comp or comp == "cert"):
            compCert = True
        elif (comp == "func"):
            compFunc = True
        elif (comp == "overflow"):
            compOverflow = True
        elif (comp == "full"):
            compCert = compFunc = compOverflow = True
        else:
            raise Exception("Invalid selection value: " + comp)

        return compCert, compFunc, compOverflow

    """
    Output stream callback function
    :param msg: message to output
    :type  msg: string
    :param delim: delimiter at the end of the string
    :type  delim: string
    """

    def log(self, msg, delim='\n'):
        self.logStream.write(str(msg) + delim)

    def showProgress(self, part, whole):
        check = int(whole / 20)
        if (part % check == 0):
            self.log('.', '')
        if (part == whole):
            self.log('')

    def printVersion(self):
        self.log("")
        self.log(getLicense())

        self.log("")
        self.log("Software Version %s" % (SOFTWARE_VERSION))
        self.log("Test Case Version %s" % (TEST_VERSION))

    """
    Calling lower level functions to parse user arguments, build test cases,
    and execute the tests through the server.
    """

    def runTest(self):
        fqdn, _ = self.build()

        self.log("Starting SSL/TLS X509 Certificate Test")
        complete = True
        cases = TestSet(fqdn, self)

        if (self.list):
            self.log("\nLegends:")
            self.log("(>) means test group or branch node")
            self.log("(*) means critical test case")
            self.log("(+) means extended test case")
            self.log("(-) means normal test case")
            self.log("\nTest Cases:")
            cnt = cases.printAllTestCases(TestCase, "")
            self.log("Total of " + str(cnt) + " test case(s).")
        elif (self.conly):
            cases.build()
            self.log("Done")
        elif (self.pver):
            self.printVersion()
        else:
            cases = cases.build()
            test = TestServer(cases.getTestSet(), cases.getBaseCase(), self)
            complete = test.run()

        self.log('')
        self.log("Program Exits" + (" with Errors" if not complete else
                                    " Correctly"))
        self.logStream.close()
