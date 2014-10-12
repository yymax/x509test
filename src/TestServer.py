"""
This file contains the SSL/TLS server logic that executes the given list
of test cases. It establishes a SSL/TLS server, sends the parameters
and certificates specified by the test case, and generate the result.
If the server is able to read any data from the secured socket, it
assumes the client accepts the test parameters. If an exception is
encountered while trying to read from the same socket, it assumes the
client reject the parameters. The server uses a new session for each
test case.

@author: Calvin Jia Liang
Created on May 15, 2014
"""

from src.TestSet import *

# TestServer class that represents a SSL/TLS test server.


class TestServer:

    """
    TestServer constructor
    :param testCases: list of test cases to be executed
    :type  testCases: list of TestCase object
    :param baseCase: the basic and valid setting and parameters
    :type  baseCase: TestCase object
    :param opt: user options
    :type  opt: Terminal object (for now)
    :returns: TestServer object
    """

    def __init__(self, testCases, baseCase, opt):
        self.testCases = testCases
        self.baseCase = baseCase
        self.opt = opt

    """
    Initialize the server
    :param addr: IPv4 address of the server
    :type  addr: string
    :param port: TCP port number to listen
    :type  port: integer
    :param sslVer: SSL/TLS version
    :type  sslVer: pyOpenSSL macro
    :returns: pyOpenSSL Connection object
    """

    def initServer(self, addr, port, sslVer):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server = SSL.Connection(SSL.Context(sslVer), sock)
        server.bind((addr, port))
        server.listen(1)
        server.setblocking(True)
        return server

    """
    Load the test server with a single test case and clean up afterward
    :param server: server that runs the test
    :type  server: pyOpenSSL Connection object
    :param test: test case to run
    :type  test: TestCase object
    :param sslVer: SSL/TLS version
    :type  sslVer: pyOpenSSL macro
    :returns: boolean
    """

    def runTest(self, server, test, sslVer):
        try:
            sslVer = test.getSSLVersion() if test.getSSLVersion() else sslVer
            ctx = SSL.Context(sslVer)
            ctx.use_privatekey_file(test.getKeyPath())
            ctx.use_certificate_chain_file(test.getPemPath())
            ctx.set_cipher_list(test.getCipherSuite())

            server.set_context(ctx)
        except (ValueError, SSL.Error):
            return None

        rlist = [server]
        cont = True
        while (cont):
            try:
                if (VERBOSE):
                    self.opt.log("Awaiting connection...")
                r, _, _ = select.select(rlist, [], [])
            except Exception as e:
                self.opt.log(str(e))
                break

            for conn in r:
                if (conn == server):
                    cli, _ = server.accept()
                    rlist = [cli]
                elif (conn is not None):
                    try:
                        conn.recv(1024)
                        connected = True
                    except (SSL.WantReadError, SSL.WantWriteError,
                            SSL.WantX509LookupError):
                        if (VERBOSE):
                            self.opt.log(str(e))
                        continue
                    except (SSL.ZeroReturnError, SSL.Error) as e:
                        if (VERBOSE):
                            self.opt.log(str(e))
                        connected = False
                    cont = False
                else:
                    cont = False

        try:
            cli.shutdown()
        except SSL.Error as e:
            if (VERBOSE):
                self.opt.log(str(e))

        return connected == test.getTestType()

    """
    Execute a test case and determine the result based on different mode
    :param server: server that runs the test
    :type  server: pyOpenSSL Connection object
    :param test: test case to run
    :type  test: TestCase object
    :param sslVer: SSL/TLS version
    :type  sslVer: pyOpenSSL macro
    :returns: boolean
    """

    def execute(self, server, test, sslVer):
        if (not self.opt.diligent):
            passed = self.runTest(server, test, sslVer)
        else:
            out = 0
            for _ in range(REPEAT):
                cnt = 0
                for _ in range(REPEAT):
                    passed = self.runTest(server, test, sslVer)
                    cnt += 1 if passed else 0
                if ((cnt == 0 or cnt == REPEAT) and
                        self.runTest(server, self.baseCase, sslVer)):
                    break
                out += 1
            if (out == REPEAT):
                forcedExit("Invalid behavior encountered.")

        return passed

    """
    Post processing and output of results
    :param passed: assert if test case passed; None for unsupported test case
    :type  passed: boolean/None
    :param test: test case that just ran
    :type  test: TestCase object
    """

    def output(self, passed, test):
        if (test.isFunctional()):
            if (passed is None):
                res = "? Unsupported"
            else:
                res = ": Accepted" if passed else "- REJECTED"
            print("{:>16} {:}".format(test.getTestName(), res))
        else:
            if ((passed and not self.opt.quiet) or not passed):
                if (passed is None):
                    res = "Unsupported"
                else:
                    res = "Passed" if passed else "FAILED"
                kind = "positive" if test.getTestType() else "negative"

                self.opt.log(res + " " + kind + " test: " + test.getTestName())
                test.printMsg(passed)

            if (not passed and test.getCritical() and not self.opt.all):
                self.opt.log("- failed a dependency test, excluding " +
                             "descendant test cases...")
                for c in self.testCases[:]:
                    for p in test.__class__.__bases__:
                        if (isinstance(c, p)):
                            self.opt.log("  > " + str(c.getTestName()))
                            self.testCases.remove(c)

    """
    Run the test server
    :returns: boolean
    """

    def run(self):
        nfails = 0
        ntests = 0

        addr = self.opt.addr
        port = self.opt.port
        sslVer = self.opt.sslVer

        self.opt.log("Starting Network Server...")
        server = self.initServer(addr, port, sslVer)

        self.opt.log("Server Ready!")
        self.opt.log("")
        for test in self.testCases:
            passed = self.execute(server, test, sslVer)
            self.output(passed, test)

            if (not test.isFunctional()):
                nfails += 0 if passed else 1
                ntests += 1

        server.close()

        if (ntests):
            if (nfails):
                self.opt.log("Your SSL/TLS client did not pass " +
                             str(nfails) + " test(s) out of " +
                             str(ntests) + " total test(s).")
            else:
                self.opt.log("Congratulations! Your SSL/TLS client passed all "
                             + str(ntests) + " test(s).")
        return True
