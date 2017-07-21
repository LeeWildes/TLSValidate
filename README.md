# TLSValidate

## Overview

**This project is built on top of Thomas Pornin's TestSSLServer and leverages
a lot of the functionality from his program to create this unique version. As
well I have maintained parts of the README since they are relevant in this
program as well**
[TestSSLServer](https://github.com/pornin/TestSSLServer/);

**TLSValidate** is a command-line tool which contacts a SSL/TLS server
and obtains some information on its configuration, without the
requirement of the server being Internet-reachable. You can use
TLSValidate on your internal network, to test your servers while they
are not (yet) accessible from the outside.

TLSValidate is unique because it displays only the issues with your server
instead of displaying all of the configurations.

Gathered and tested information includes the following:

 - Supported protocol versions (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 and
   TLS 1.2 are tested).

 - For each protocol version, the supported cipher suites; an attempt
   is also made at determining the algorithm used by the server to
   select the cipher suite.

 - Preferred ciphersuite ordering and weak/broken ciphersuites are
   checked.

 - Certificate(s) used by the server, which are then locally decoded to
   determine key type, size, and hash function used in the signature.

The analysis is performed by repeatedly connecting to the target server,
with different variants of `ClientHello` messages, and analysing the
server's answer. It shall be noted that TLSValidate includes no
cryptographic algorithm whatsoever; as such, it is incapable of
completing any SSL/TLS handshake. It sends a `ClientHello`, then obtains
the server's response up to the next `ServerHelloDone` message, at which
points it closes the connection.

**Note:** although the information which is gathered from the server is
nominally public, some server administrators could be somewhat dismayed
at your using the tool on their servers, and there may be laws against
it (in the same way that port scanning third-party servers with `nmap`
is a matter of delicacy, both morally and legally). You should use
TLSValidate only to scan your own servers, and that's what it was
designed to do.

## License

License is MIT-like: you acknowledge that the code is provided without
any guarantee of anything, and that I am not liable for anything which
follows from using it. Subject to these conditions, you can do whatever
you want with the code. See the `LICENSE` file in the source code for
the legal wording.

## Installation

The source code is obtained from
[GitHub](https://github.com/LeeWildes/TLSValidate); use the "Download
ZIP" to obtain a fresh snapshot, or use `git` to clone the repository.
In the source tree, you will find the simple build scripts, `build.cmd`
(for Windows) and `build.sh` (for Linux and OS X).

The Windows script invokes the command-line compiler (`csc.exe`) that is
found in the v2.0.50727 .NET framework. This framework is installed by
default on Windows 7. More recent versions of Windows do not have the
.NET 2.0 framework, but a more recent version (4.x or later). Though
these framework versions are not completely compatible with each other,
TLSValidate uses only features that work identically on both, so you
can compile TLSValidate with either .NET version. The resulting
TLSValidate.exe is stand-alone and needs no further "installation";
you simply copy the file where you want it to be, and run it from a
console (`cmd.exe`) with the appropriate arguments.

The Linux / OS X script tries to invoke the Mono C# compiler under the
names `mono-csc` (which works on Ubuntu) and `dmcs` (which works on OS
X). On Ubuntu, install the `mono-devel` package; it should pull as
dependencies the runtime and the compiler. On OS X, fetch a package from
the [Mono project](http://www.mono-project.com/) and install it; it
should provide the `mono` command-line tool to run compiled asemblies,
and `dmcs` to invoke the C# compiler.

## Usage

On Windows, the compiled `TLSValidate.exe` file can be launched as
is. On Linux and OS X, use `mono TLSValidate.exe`.

General usage:

    TLSValidate.exe [ options ] servername [ port ]

The `servername` is the name of IP address of the target server. If the
`port` is not specified, then 443 is used.

Options are:

 - `-h`

   Print an helper message. You also get it by running the tool without
   any argument.

 - `-v`

   Enable verbose operations. During data gathering, TLSValidate will
   print some information that documents the actions; in particular, it
   will display an extra "`.`" character for each connection.

 - `-all`

   Gather information for all possible cipher suites. By default,
   TLSValidate only tests for the cipher suites that it knows about,
   which are the (currently) 323 cipher suites registered at the
   [IANA](http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4).
   With the `-all` command-line flag, TLSValidate will test for all
   possible 65533 cipher suites (excluding the special cipher suites
   0x0000, 0x00FF and 0x5600, which are not real cipher suites).

 - `-min version`

   Test only protocol versions greater than or equal to the specified
   version (the version is specified as a string: `SSLv2`, `SSLv3`,
   `TLSv1`, `TLSv1.1` or `TLSv1.2`).

 - `-max version`

   Test only protocol versions lower than or equal to the specified
   version (the version is specified as a string: `SSLv2`, `SSLv3`,
   `TLSv1`, `TLSv1.1` or `TLSv1.2`).

 - `-sni name`

   Set the "server name" to be sent as part of the Server Name Extension
   (SNI) in the `ClientHello` message. By default, the SNI will contain
   a copy of the `servername` command-line parameter; this option allows
   to override the name. By using the name "`-`", the SNI extension is
   disabled.

 - `-certs`

   In the output report, include the full server certificate(s) in PEM
   format.

 - `-t delay`

   Set the timeout delay (in seconds). This timeout is applied when
   waiting for response bytes from the server, for the SSLv2 test
   connection, and for the SSLv3/TLS connections until an actual
   SSL-like answer was obtained (a ServerHello or an alert). If the
   timeout is reached for SSLv3/TLS, then the server is assumed to
   implement a non-SSL protocol, and processing stops.

   By default, a 20-second delay is applied, so that connecting to a
   non-SSL server may not stall for more than 40 seconds. Use 0 to
   deactivate the timeout (read will block indefinitely).

 - `-prox name:port`

   Use the specified HTTP proxy to perform connections to the server.
   (TLSValidate does not support proxy authentication yet.)

 - `-proxssl`

   Use SSL/TLS to open the connection to the HTTP proxy.

 - `-ec`

   Add a "supported curves" extension to the `ClientHello` for most
   connections, testing extension-less EC support only at the end of the
   process. This is the default and it maximizes the chances of
   detection of elliptic-curve based cipher suites: some servers might
   not allow negotiation of an EC cipher suite in the absence of the
   extension.

 - `-noec`

   Do not add a "supported curves" extension in the `ClientHello` for
   most connections. That extension will be added only for some specific
   connections at the end, and only if the server still selected some
   EC-based suites. This option should be used only if a target server
   appears to be allergic to elliptic curves and refuses to respond in
   the presence of the "supported curves" extension.

   Using this extension may miss some supported cipher suites, if the
   server does not support EC-based suites without the client extension.

 - `-text fname`

   Produce a text report (readable by humans) into the designated
   file. If `fname` is "`-`", then the report is written on standard
   output.

   If neither `-text` nor `-json` is used, the text report will be
   written on standard output.

 - `-html fname`

   Creates an html file which will give you the same report but with
   links on the issues. The links lead to solutions and further
   explanation

 - `-json fname`

   **Under Construction**

   Produce a JSON report (parsable) into the designated file. If `fname`
   is "`-`", then the report is written on standard output.

   If neither `-text` nor `-json` is used, the text report will be
   written on standard output.

 - `-log fname`

   Produce a text-based log of all connection attempts (hexadecimal dump
   of all bytes in both directions) in the specified file.

For example, to make a text report in file "test.txt" for server
"www.example.com" on port 443, use:

    TLSValidate.exe -v -text test.txt www.example.com 443

## JSON Format

**Under Construction**

## Text Output

This is a snippet of what part of a text file would look like.

 Connection: facebook.com:443  
 SNI: facebook.com  
  TLSv1.0 is Not Approved - please remove  
  Testing on TLSv1.1:  

  Cipher Ordering Not Approved  
  Here is the recommended ordering  
     ECDHE_ECDSA_WITH_AES_128_CBC_SHA  
     ECDHE_ECDSA_WITH_AES_256_CBC_SHA  
     ECDHE_RSA_WITH_AES_128_CBC_SHA  
     ECDHE_RSA_WITH_AES_256_CBC_SHA  
     RSA_WITH_AES_128_CBC_SHA  
     RSA_WITH_AES_256_CBC_SHA  
  Remove these ciphers - Not Approved  
     ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  
     - 3DES is a weak cipher suite  
     ECDHE_RSA_WITH_3DES_EDE_CBC_SHA  
     - 3DES is a weak cipher suite  
     RSA_WITH_3DES_EDE_CBC_SHA  
     - 3DES is a weak cipher suite  
     ECDHE_ECDSA_WITH_RC4_128_SHA  
     - RC4 is a broken cipher suite  
     ECDHE_RSA_WITH_RC4_128_SHA  
     - RC4 is a broken cipher suite  
     RSA_WITH_RC4_128_SHA  
     - RC4 is a broken cipher suite  

## Some Notes

### Weak Suites and Keys

In SSL/TLS, client and server negotiate security parameters. Therefore,
if both support strong cipher suites and keys, all should be fine,
even if they would potentially support weak cipher suites as well?

Not so fast. The handshake is protected: once the cryptography has
occurred, the client and server send verification messages (`Finished`),
protected by the newly negotiated algorithms and keys, and the contents
of these messages are basically a hash of all preceding messages,
including the `ClientHello`. Therefore, alterations by attackers, who
try to make client and server negotiate a weak cipher suite, should be
detected at that point. _Unless_ the weak cipher suite is so weak that
it can be broken right away, dynamically, so that the attacker can then
unravel the encryption in real time, and "fix" the `Finished` messages.

This is exactly what was done with the so-called "Logjam" and "FREAK"
attacks, that rely on support of export cipher suites with awfully weak
key exchange parameters (512-bit RSA or DH).

On a similar note, a recent attack ("DROWN" -- yet another example of
that weird fashion of witty acronyms) leverages SSL 2.0 support to break
a TLS key exchange that used the same private key. That attack is a
clear example of how support for a weak protocol version can be harmful
even if normal clients do not use it.

Therefore, **all weak cipher suites and keys should be disabled**.


### Untested Conditions

TLSValidate does not try to push the server implementation to its
limits. Its goal is not to find implementation flaws, only configuration
flaws.

For instance, TLSValidate does not try to test the quality of the
random generation on the server side; it does not either check that the
sent DH or ECDH parameters, or the server's public/private key pair, are
mathematically sound.

Since TLSValidate never completes any handshake, it cannot test for
post-handshake options, in particular whether the server would allow
renegotiations at all.

Some tests that TLSValidate does not perform right now, but may
implement in a future version:

 - Detection of support of other extensions such as Maximum Fragment
   Length, Truncated HMAC, or OCSP stapling.

 - Detection of reuse of (EC)DH parameters. In DHE and ECDHE cipher
   suites, the server sends ephemeral key exchange parameters, but it
   may keep them around for some time. The longer such parameters are
   reused, the less "forward secure" the connection becomes, so this is
   a trade-off between efficiency and security.

 - Support for session tickets (RFC 5077).

 - Better analysis of X.509 certificates. TLSValidate could, for
   instance, try to validate the server chain with the platform-provided
   facilities (System.Security.Cryptography.X509Certificates). Ideally,
   it would include its own, extension X.509 validation library, but
   this is considerable work, both for development and maintenance, so
   it will probably not happen any time soon (or ever).

## Author

Question and comments can be sent to: Lee Wildes `<leeawildes@gmail.com>`
