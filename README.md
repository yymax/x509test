x509test
========

If you have any questions, suggestions, comments, concerns, or interesting stories, please email <x509test@gmail.com>. 

Description:

x509test is a software written in Python 3 that test the x509 certificate verification process of the target SSL/TLS client. The inspiration of this software comes from multiple reports on the insecurity of a SSL/TLS clients due to incorrect verification of x509 certificate chain. This phenomenon is caused by many factors. One of which is the lack of negative feedback from over-acceptance of invalid certificates. This software is an attempt to increase the security of a client-side SSL/TLS software by providing negative feedbacks to the developers. 

Test Procedure:

1. The software takes in a user supplied fqdn, where the fqdn is the destination of the client connection

2. The software reads the certificate and key of the root CA. If no root CA is specified, the software generate a self-signed certificate that acts as the root CA.
(NOTE: the root certificate must be trusted by the client software; either by including it to the OS’s trust store or manually configure the client software to trust the certificate.)

3. The software generates a set of test certificates. Some are signed directly by the root CA while others are chained with other intermediate CAs. The majority of the test certificates contain flaws.

4. The software starts a SSL/TLS server and waits for a client to connect. Each session corresponds to a single test certificate chain. If the client completes the handshake procedure with an invalid certificate chain, or terminates the handshake procedure with a valid certificate chain, then the software will denote such behavior as a potential violation. Regardless of the outcome, the software always terminate the connection once result is obtained and start a new session with a different test certificate chain.
(NOTE: some port requires root privilege, so it is recommended to run this software in root.)

5. Results will be printed to the terminal, or a file if specified, as the test progresses. There are only three possible results from a given test. Pass means no non-compliance behavior is observed; fail means non-compliance behavior encountered; unsupported means the underlying system in which x509test is running on does not support the perticular test.

Dependencies:

Python 3.2 or up
pyOpenSSL 0.14 or up
pyasn1 0.1.7 or up
pyasn1_modules 0.0.5 or up
OpenSSL 1.0.1 or up 

Installation:

Currently, no installation procedure is needed. After all dependencies are installed, simply go to the X509Test folder and run x509test.py using python interpreter to start the program.

Example Run:

All following examples use www.tls.test as the fqdn, which means it is pretending to be the server of the (fake) site www.tls.test.

All following examples assume Linux-based OS. Windows users should run the command prompt as administrator (equivalent of sudo) and specify the path to your python3.exe executable file (equivalent of python3).

All following examples assume the current working directory is X509Test (the downloaded folder that contains x509test.py and other items.)

1. A server listens on port 443 with an IPv4 address of 10.1.2.3
   sudo python3 x509test.py www.tls.test -a 10.1.2.3 -p 443

2. A server listens on port 8080 with an loop back address, and rebuild all test cases
   sudo python3 x509test.py www.tls.test -r -p 8080

3. List all available test cases (fqdn can be any string)
   python3 x509test.py fqdn -l

4. Run functionality test only
   sudo python3 x509test.py www.tls.test -c func

5. Run both functionality and certificate tests with SSL3
   sudo python3 x509test.py www.tls.test -c full --ssl SSLv3

6. The root certificate is encrypted with password 'secret'
   sudo python3 x509test.py www.tls.test --ca-password secret

7. Print the current version and license of the software (fqdn can be any string)
   python3 x509test.py fqdn --version

More options can be found by using --help
   python3 x509test.py fqdn --help 

Why use x509test:

1. Security is hard
2. x509test is easy to use
3. x509test is open-source
4. x509test is free


Thank you for using x509test.
