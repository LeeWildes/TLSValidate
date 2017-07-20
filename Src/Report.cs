using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Text;
using System.Web.UI;

/*
 * This class accumulates the information about the tested server,
 * and produces the report.
 */

class Report
{


    /*
	 * Connection name (server name).
	 */
    internal string ConnName
    {
        get
        {
            return connName;
        }
        set
        {
            connName = value;
        }
    }

    /*
	 * Connection port.
	 */
    internal int ConnPort
    {
        get
        {
            return connPort;
        }
        set
        {
            connPort = value;
        }
    }

    /*
	 * Server name sent in the SNI extension. This may be null if
	 * no SNI extension was sent.
	 */
    internal string SNI
    {
        get
        {
            return sni;
        }
        set
        {
            sni = value;
        }
    }

    /*
	 * List of supported SSLv2 cipher suites, in the order returned
	 * by the server (which is purely advisory, since selection is
	 * done by the client). It is null if SSLv2 is not supported.
	 */
    internal int[] SSLv2CipherSuites
    {
        get
        {
            return ssl2Suites;
        }
        set
        {
            ssl2Suites = value;
        }
    }

    /*
	 * Certificate sent by the server if SSLv2 is supported (null
	 * otherwise). It is reported as a chain of length 1.
	 */
    internal X509Chain SSLv2Chain
    {
        get
        {
            return ssl2Chain;
        }
    }

    /*
	 * List of supported cipher suites, indexed by protocol version.
	 * This map contains information for version SSL 3.0 and more.
	 */
    internal IDictionary<int, SupportedCipherSuites> CipherSuites
    {
        get
        {
            return suites;
        }
    }

    /*
	 * Support for SSLv3+ with a SSLv2 ClientHello format.
	 */
    internal bool SupportsV2Hello
    {
        get
        {
            return helloV2;
        }
        set
        {
            helloV2 = value;
        }
    }

    /*
	 * Set to true if we had to shorten our ClientHello messages
	 * (this indicates a server with a fixed, small buffer for
	 * incoming ClientHello).
	 */
    internal bool NeedsShortHello
    {
        get
        {
            return shortHello;
        }
        set
        {
            shortHello = value;
        }
    }

    /*
	 * Set to true if we had to suppress extensions from our
	 * ClientHello (flawed server that does not support extensions).
	 */
    internal bool NoExtensions
    {
        get
        {
            return noExts;
        }
        set
        {
            noExts = value;
        }
    }

    /*
	 * Set to true if the server, at some point, agreed to use
	 * Deflate compression.
	 */
    internal bool DeflateCompress
    {
        get
        {
            return compress;
        }
        set
        {
            compress = value;
        }
    }

    /*
	 * Set to true if the server appears to support secure
	 * renegotiation (at least, it understands and returns an empty
	 * extension; this does not demonstrate that the server would
	 * accept an actual renegotiation, but if it does, then chances
	 * are that it will tag it with the proper extension value).
	 */
    internal bool SupportsSecureRenegotiation
    {
        get
        {
            return doesRenego;
        }
        set
        {
            doesRenego = value;
        }
    }

    /*
	 * Set to true if the server appears to support the Encrypt-then-MAC
	 * extension (RFC 7366). This is only about the extension, _not_
	 * cipher suites that are "natively" in Encrypt-then-MAC mode (e.g.
	 * AES/GCM and ChaCha20+Poly1305 cipher suites).
	 */
    internal bool SupportsEncryptThenMAC
    {
        get
        {
            return doesEtM;
        }
        set
        {
            doesEtM = value;
        }
    }

    /*
	 * Set the server time offset (serverTime - clientTime), in
	 * milliseconds.
	 *
	 * Int64.MinValue means that the server sends 0 (the standard
	 * method to indicate that the clock is not available).
	 *
	 * Int64.MaxValue means that the server sends random bytes
	 * in the time field (non-standard, but widespread because
	 * OpenSSL does that by default since September 2013).
	 */
    internal long ServerTimeOffset
    {
        get
        {
            return serverTimeOffset;
        }
        set
        {
            serverTimeOffset = value;
        }
    }

    /*
	 * Minimal size (in bits) of DH parameters sent by server. If
	 * server never used DHE or SRP, then this is 0.
	 */
    internal int MinDHSize
    {
        get
        {
            return minDHSize;
        }
        set
        {
            minDHSize = value;
        }
    }

    /*
	 * Get all certificate chains gathered so far.
	 */
    internal X509Chain[] AllChains
    {
        get
        {
            return M.ToValueArray(chains);
        }
    }

    string connName;
    int connPort;
    string sni;
    int[] ssl2Suites;
    X509Chain ssl2Chain;
    bool helloV2;
    bool shortHello;
    bool noExts;
    IDictionary<int, SupportedCipherSuites> suites;
    IDictionary<string, X509Chain> chains;
    bool compress;
    long serverTimeOffset;
    bool doesRenego;
    bool doesEtM;
    int minDHSize;

    /*
	 * Create an empty report instance.
	 */
    internal Report()
    {
        suites = new SortedDictionary<int, SupportedCipherSuites>();
        chains = new SortedDictionary<string, X509Chain>(
            StringComparer.Ordinal);
        serverTimeOffset = Int64.MinValue;
    }

    /*
	 * Set the cipher suites supported for a specific protocol version
	 * (SSLv3+).
	 */
    internal void SetCipherSuites(int version, SupportedCipherSuites scs)
    {
        suites[version] = scs;
    }

    /*
	 * Record a certificate sent by a SSLv2 server. The certificate
	 * is alone.
	 */
    internal void SetSSLv2Certificate(byte[] ssl2Cert)
    {
        if (ssl2Cert == null)
        {
            ssl2Chain = null;
        }
        else
        {
            ssl2Chain = X509Chain.Make(
                new byte[][] { ssl2Cert }, true);
        }
    }

    /*
	 * Record a new certificate chain sent by the server. Duplicates
	 * are merged.
	 */
    internal void AddServerChain(byte[][] chain)
    {
        X509Chain xc = X509Chain.Make(chain, true);
        chains[xc.Hash] = xc;
    }


    /*
	 * Print the report on the provided writer (text version for
	 * humans).
	 */
    internal void Print(TextWriter w)
    {
        w.WriteLine("Connection: {0}:{1}", connName, connPort);
        if (sni == null)
        {
            w.WriteLine("No SNI sent");
        }
        else
        {
            w.WriteLine("SNI: {0}", sni);
        }
        if (ssl2Suites != null && ssl2Suites.Length > 0)
        {
            w.WriteLine("  {0}", M.VersionString(M.SSLv20));
            foreach (int s in ssl2Suites)
            {
                w.WriteLine("     {0}",
                    CipherSuite.ToNameV2(s));
            }
        }
        int protocolCount = 0;
        foreach (int v in suites.Keys)
        {
            if (String.Compare(M.VersionString(v), "TLSv1.0") == 0 ||
                String.Compare(M.VersionString(v), "SSLv2") == 0 ||
                String.Compare(M.VersionString(v), "SSLv3") == 0)
            {
                w.WriteLine("  {0} is Not Approved - please remove", M.VersionString(v));
                protocolCount = protocolCount + 1;

                if (suites.Keys.Count == protocolCount)
                {
                    w.WriteLine("  Please add at least one approved SSL/TLS protocol");
                }
            }

            else
            {
                w.Write("  Testing on {0}:", M.VersionString(v));

                SupportedCipherSuites scs = suites[v];
                w.WriteLine();
                w.WriteLine();

                if (!(scs.PrefServer))
                {
                    w.Write("  Server Selection: ");
                    w.Write("Not Approved");
                    if (scs.PrefClient)
                    {
                        w.WriteLine("  - Uses client preferences - Needs to support server preferences");
                    }
                    else
                    {
                        w.WriteLine("  - uses complex preferences - Needs to support server preferences");
                    }
                    w.WriteLine();
                }

                List<String> notApproved = new List<String>();
                List<String> approved = new List<String>();

                if (String.Compare(M.VersionString(v), "TLSv1.0") != 0)
                {
                    bool correctOrdering = true;

                    foreach (int s in scs.Suites)
                    {

                        String cipher = CipherSuite.ToName(s);
                        if (cipher.Contains("APPROVED"))
                        {
                            approved.Add(cipher.Substring(0, cipher.Length - 9));
                        }
                        else
                        {
                            correctOrdering = false;
                            notApproved.Add(cipher);
                        }

                    }
                    List<String> temp = cipherOrdering(approved);
                    if (correctOrdering)
                    {
                        for (int i = 0; i < temp.Count; i++)
                        {
                            if (!(temp[i].Equals(approved[i])))
                            {
                                correctOrdering = false;
                            }
                        }
                    }

                    if (correctOrdering)
                    {
                        w.WriteLine("  Cipher Ordering Approved");
                    }
                    else
                    {
                        w.WriteLine("  Cipher Ordering Not Approved");
                        w.WriteLine("  Here is the recommended ordering");
                        approved = cipherOrdering(approved);
                        foreach (String s in approved)
                        {
                            w.WriteLine("     {0}", s);
                        }

                        if (notApproved.Count > 0)
                        {
                            w.WriteLine("  Remove these ciphers - Not Approved");
                            foreach (String s in notApproved)
                            {
                                w.WriteLine("     {0}", s);
                                if (s.Contains("RC4"))
                                {
                                    w.WriteLine("     - RC4 is a broken cipher suite");
                                }
                                if (s.Contains("3DES"))
                                {
                                    w.WriteLine("     - 3DES is a weak cipher suite");
                                }
                            }
                        }
                    }
                    approved.Clear();
                    notApproved.Clear();
                    w.WriteLine();
                }
            }
        }
        w.WriteLine();
        w.WriteLine("=========================================");
        if (minDHSize < 2048 && minDHSize > 0)
        {
            w.WriteLine("DH size is {0}", minDHSize);
            w.WriteLine("DH should be 2048 or above.");

        }
        if (ssl2Chain != null)
        {
            if (checkKeySize(ssl2Chain, 0))
            {
                w.WriteLine("+++++ SSLv2 certificate - Not Approved");
                PrintCert(w, ssl2Chain, 0);
            }
        }

        String chainCount = "+++++ SSLv3/TLS: certificate chain(s) - Not Approved";
        foreach (X509Chain xchain in chains.Values)
        {
            int n = xchain.Elements.Length;
            for (int i = 0; i < n; i++)
            {
                bool flag = true;
                if (checkKeySize(xchain, i))
                {
                    if (flag) // I'm not sure what this is needed for. Do further testing.
                    {
                        w.WriteLine(chainCount);
                        flag = false;
                    }
                    PrintCert(w, xchain, i);
                }
            }
        }
    }

    bool checkKeySize(X509Chain xchain, int num)
    {
        X509Cert xc = xchain.ElementsRev[num];

        if (xc == null)
            return true;
        else if (xc.KeySize < 2048 && xc.KeyType.Contains("RSA"))
            return true;
        else if (xc.KeySize < 1024 && xc.KeyType.Contains("DSA"))
            return true;
        else if (xc.KeySize < 256)
            return true;

        return false;
    }

    void PrintCert(TextWriter w, X509Chain xchain, int num)
    {
        X509Cert xc = xchain.ElementsRev[num];

        if (xc == null)
        {
            w.WriteLine("thumprint:  {0}", xchain.ThumbprintsRev[num]);
            w.WriteLine("UNDECODABLE: {0}",
                xchain.DecodingIssuesRev[num]);
        }
        else
        {
            if (xc.KeySize < 2048)
            {
                if (xc.KeyType.Contains("EC") && xc.KeySize < 256)
                {
                    w.WriteLine("Key size should be 256 or larger for {0}", xc.KeyType);
                }
                else if (xc.KeyType.Contains("DSA") && xc.KeySize < 1024)
                {
                    w.WriteLine("Key size should be 1024 or larger for {0}", xc.KeyType);
                }
                else if (xc.KeyType.Contains("RSA"))
                {
                    w.WriteLine("Key size should be 2048 or larger for {0}", xc.KeyType);
                }
                else
                {
                    return;
                }

                w.WriteLine(" thumprint:  {0}", xchain.ThumbprintsRev[num]);
                w.WriteLine("Current key size:   {0}", xc.KeySize);
            }
        }
    }

    void PrintCertHtml(HtmlTextWriter w, X509Chain xchain, int num)
    {
        X509Cert xc = xchain.ElementsRev[num];

        if (xc == null)
        {
            w.WriteBeginTag("p");
            w.Write(HtmlTextWriter.TagRightChar);
            w.WriteLine("thumprint:  {0}", xchain.ThumbprintsRev[num]);
            w.WriteEndTag("p");
            w.WriteBeginTag("p");
            w.Write(HtmlTextWriter.TagRightChar);
            w.WriteBeginTag("a");
            w.Write(" href=");
            w.Write(" 'JavaScript: newPopup(\"/TLSValidate/keySize\");'");
            w.WriteLine("UNDECODABLE: {0}",
                xchain.DecodingIssuesRev[num]);
            w.WriteEndTag("a");
            w.WriteEndTag("p");
        }
        else
        {
            if (xc.KeySize < 2048)
            {
                if (xc.KeyType.Contains("EC") && xc.KeySize < 256)
                {
                    w.WriteBeginTag("p");
                    w.Write(HtmlTextWriter.TagRightChar);
                    w.WriteBeginTag("a");
                    w.Write(" href=");
                    w.Write(" 'JavaScript: newPopup(\"/TLSValidate/keySize\");'");
                    w.Write(HtmlTextWriter.TagRightChar);
                    w.WriteLine("Key size should be 256 or larger for {0}", xc.KeyType);
                    w.WriteEndTag("a");
                    w.WriteEndTag("p");
                }
                else if (xc.KeyType.Contains("DSA") && xc.KeySize < 1024)
                {
                    w.WriteBeginTag("p");
                    w.Write(HtmlTextWriter.TagRightChar);
                    w.WriteBeginTag("a");
                    w.Write(" href=");
                    w.Write(" 'JavaScript: newPopup(\"/TLSValidate/keySize\");'");
                    w.Write(HtmlTextWriter.TagRightChar);
                    w.WriteLine("Key size should be 1024 or larger for {0}", xc.KeyType);
                    w.WriteEndTag("a");
                    w.WriteEndTag("p");
                }
                else if (xc.KeyType.Contains("RSA"))
                {
                    w.WriteBeginTag("p");
                    w.Write(HtmlTextWriter.TagRightChar);
                    w.WriteBeginTag("a");
                    w.Write(" href=");
                    w.Write(" 'JavaScript: newPopup(\"/TLSValidate/keySize\");'");
                    w.Write(HtmlTextWriter.TagRightChar);
                    w.WriteLine("Key size should be 2048 or larger for {0}", xc.KeyType);
                    w.WriteEndTag("a");
                    w.WriteEndTag("p");
                }
                else
                {
                  w.WriteBeginTag("p");
                  w.Write(HtmlTextWriter.TagRightChar);
                  w.WriteBeginTag("a");
                  w.Write(" href=");
                  w.Write(" 'JavaScript: newPopup(\"/TLSValidate/keySize\");'");
                  w.Write(HtmlTextWriter.TagRightChar);
                  w.WriteLine("Invalid key size for {0}", xc.KeyType);
                  w.WriteEndTag("a");
                  w.WriteEndTag("p");
                }

                w.WriteBeginTag("p");
                w.Write(HtmlTextWriter.TagRightChar);
                w.WriteLine(" thumprint:  {0}", xchain.ThumbprintsRev[num]);
                w.WriteLine("Current key size:   {0}", xc.KeySize);
                w.WriteEndTag("p");
            }
        }
    }

    /*
     * The ordering functions
     * recursively seperate and order
     * the ciphersuites.
     */
    internal List<String> cipherOrdering(List<String> ciphers)
    {
        List<String> AES = new List<string>();
        List<String> noAES = new List<string>();

        foreach (String c in ciphers)
        {
            if (hasAES(c))
            {
                AES.Add(c);
            }

            else
            {
                noAES.Add(c);
            }
        }

        AES = shaOrdering(AES);
        AES = GCMOrdering(AES);
        noAES = shaOrdering(noAES);
        AES.AddRange(GCMOrdering(noAES));

        return AES;

    }

    internal List<String> GCMOrdering(List<String> GCM)
    {
        List<String> GCMs = new List<string>();
        List<String> noGCM = new List<string>();

        foreach (String c in GCM)
        {
            if (hasGCM(c))
            {
                GCMs.Add(c);
            }

            else
            {
                noGCM.Add(c);
            }
        }

        GCMs = shaOrdering(GCMs);
        GCMs = ECOrdering(GCMs);
        noGCM = shaOrdering(noGCM);
        GCMs.AddRange(ECOrdering(noGCM));

        return GCMs;


    }

    internal List<String> ECOrdering(List<String> EC)
    {
        List<String> noEc = new List<string>();
        List<String> ec = new List<string>();
        foreach (String c in EC)
        {
            if (hasEC(c))
            {
                ec.Add(c);
            }

            else
            {
                noEc.Add(c);
            }
        }

        ec = shaOrdering(ec);
        ec = EphemOrdering(ec);
        noEc = shaOrdering(noEc);
        ec.AddRange(EphemOrdering(noEc));

        return ec;
    }

    internal List<String> EphemOrdering(List<String> Ephem)
    {
        List<String> noEphem = new List<string>();
        List<String> ephem = new List<string>();
        foreach (String c in Ephem)
        {
            if (hasEphem(c))
            {
                ephem.Add(c);
            }

            else
            {
                noEphem.Add(c);
            }
        }

        ephem = shaOrdering(ephem);
        ephem = DHOrdering(ephem);
        noEphem = shaOrdering(noEphem);
        ephem.AddRange(DHOrdering(noEphem));

        return ephem;
    }

    internal List<String> DHOrdering(List<String> DH)
    {
        List<String> noDh = new List<string>();
        List<String> dh = new List<string>();
        foreach (String c in DH)
        {
            if (hasDH(c))
            {
                dh.Add(c);
            }

            else
            {
                noDh.Add(c);
            }
        }

        dh = shaOrdering(dh);
        dh = RSAOrdering(dh);
        noDh = shaOrdering(noDh);
        dh.AddRange(RSAOrdering(noDh));

        return dh;

    }

    /*
     * Now we enter into the RSA,ECDSA,DSA ordering
     */

    internal List<String> RSAOrdering(List<String> RSA)
    {
        List<String> noRsa = new List<string>();
        List<String> rsa = new List<string>();
        foreach (String c in RSA)
        {
            if (hasRSA(c))
            {
                rsa.Add(c);
            }

            else
            {
                noRsa.Add(c);
            }
        }

        rsa = shaOrdering(rsa);
        rsa = ECDSAOrdering(rsa);
        noRsa = shaOrdering(noRsa);
        rsa.AddRange(ECDSAOrdering(noRsa));

        return rsa;

    }

    internal List<String> ECDSAOrdering(List<String> ECDSA)
    {
        List<String> noEc = new List<string>();
        List<String> ec = new List<string>();
        foreach (String c in ECDSA)
        {
            if (hasECDSA(c))
            {
                ec.Add(c);
            }

            else
            {
                noEc.Add(c);
            }
        }
        ec = shaOrdering(ec);
        noEc = shaOrdering(noEc);
        ec.AddRange(noEc);

        return ec;

    }

    internal List<String> shaOrdering(List<String> sha)
    {
      String smallest = "";
      int spot = 0;
      for(int i=0;i<sha.Count;i++)
      {
        for(int j=i;j<sha.Count;j++)
        {
          if(sha[j].Contains("SHA384"))
          {
            smallest = sha[j];
            spot = j;
            break;
          }
          else if(sha[j].Contains("SHA256"))
          {
            if(!(smallest.Contains("SHA384")))
            {
              smallest = sha[j];
              spot = j;
            }
          }
          else
          {
            if(!(smallest.Contains("SHA256"))&&!(smallest.Contains("SHA384")))
            {
              smallest = sha[j];
              spot = j;
            }
          }
        }
        sha[spot] = sha[i];
        sha[i] = smallest;
        smallest = "";
      }
      return sha;
    }


    /*
     * the 'has' functions check for each cipher,
     * created to make code more readable
     */

    internal bool hasRSA(String cipher)
    {
        if (cipher.Substring(1, 3).Contains("RSA"))
        {
            if (cipher.Substring(3, cipher.Length).Contains("RSA"))
            {
                return true;
            }

            else
            {
                return false;
            }
        }
        else
        {
            if (cipher.Contains("RSA"))
            {
                return true;
            }

            else
            {
                return false;
            }
        }
    }

    internal bool hasECDSA(String cipher)
    {
        if (cipher.Contains("ECDSA"))
        {
            return true;
        }

        return false;
    }

    internal bool hasAES(String cipher)
    {
        if (cipher.Contains("AES"))
        {
            return true;
        }

        return false;
    }

    internal bool hasGCM(String cipher)
    {
        if (cipher.Contains("GCM"))
        {
            return true;
        }

        return false;
    }

    internal bool hasEC(String cipher)
    {
        if (cipher.Contains("EC"))
        {
            return true;
        }

        return false;
    }

    internal bool hasEphem(String cipher)
    {
        if (cipher.Contains("DHE"))
        {
            return true;
        }

        return false;
    }

    internal bool hasDH(String cipher)
    {
        if (cipher.Contains("DH"))
        {
            return true;
        }

        return false;
    }

    /*
     * Print the report as HTML
     */
    internal void PrintHtml(TextWriter w)
    {
        HtmlTextWriter htw = new HtmlTextWriter(w);

        w.WriteLine("<!DOCTYPE html>");
        w.WriteLine("<html>");
        w.WriteLine("<head>");
        w.WriteLine("<style>");
        w.WriteLine("a {");
        w.WriteLine("color:red");
        w.WriteLine("}");
        w.WriteLine("</style>");
        htw.Write("Connection: {0}:{1}", connName, connPort);
        w.WriteLine("</head>");
        htw.WriteBeginTag("body");
        htw.Write(HtmlTextWriter.TagRightChar);
        htw.WriteBeginTag("script");
        htw.Write(" type='text/javascript'");
        htw.Write(HtmlTextWriter.TagRightChar);
        htw.WriteLine("function newPopup(url) {");
        htw.WriteLine("popupWindow = window.open(");
        htw.WriteLine("url,'popUpWindow'," +
            "'height=500,width=500,left=10,top=10,resizable=yes," +
            "scrollbars=yes,toolbar=yes,menubar=no,location=no," +
            "directories=no,status=yes')}");
        htw.WriteEndTag("script");

        if (ssl2Suites != null && ssl2Suites.Length > 0)
        {
            // htw.WriteBeginTag("script");
            // htw.Write(" type='text/javascript'");
            // htw.Write(HtmlTextWriter.TagRightChar);
            // htw.WriteLine("function newPopup(url) {");
            // htw.WriteLine("popupWindow = window.open(");
            // htw.WriteLine("url,'popUpWindow'," +
            //     "'height=500,width=500,left=10,top=10,resizable=yes," +
            //     "scrollbars=yes,toolbar=yes,menubar=no,location=no," +
            //     "directories=no,status=yes')}");
            // htw.WriteEndTag("script");
            htw.WriteBeginTag("p");
            htw.Write(HtmlTextWriter.TagRightChar);
            htw.WriteBeginTag("a");
            htw.Write(" href=");
            htw.Write(" 'JavaScript: newPopup(\"/TLSValidate/SSL\");'");
            htw.Write(HtmlTextWriter.TagRightChar);
            htw.WriteLine("  {0} is Not Approved - please remove", M.VersionString(M.SSLv20));
            htw.WriteEndTag("a");
            htw.WriteEndTag("p");
        }

        int protocolCount = 0;
        foreach (int v in suites.Keys)
        {
            if (String.Compare(M.VersionString(v), "TLSv1.0") == 0 ||
                String.Compare(M.VersionString(v), "SSLv3") == 0)
            {
                // htw.WriteBeginTag("script");
                // htw.Write(" type='text/javascript'");
                // htw.Write(HtmlTextWriter.TagRightChar);
                // htw.WriteLine("function newPopup(url) {");
                // htw.WriteLine("popupWindow = window.open(");
                // htw.WriteLine("url,'popUpWindow'," +
                //     "'height=500,width=500,left=10,top=10,resizable=yes," +
                //     "scrollbars=yes,toolbar=yes,menubar=no,location=no," +
                //     "directories=no,status=yes')}");
                // htw.WriteEndTag("script");
                htw.WriteBeginTag("p");
                htw.Write(HtmlTextWriter.TagRightChar);
                htw.WriteBeginTag("a");
                htw.Write(" href=");
                if (String.Compare(M.VersionString(v), "TLSv1.0") == 0)
                {
                    htw.Write(" 'JavaScript: newPopup(\"/TLSValidate/TLS1\");'");
                }
                else
                {
                    htw.Write(" 'JavaScript: newPopup(\"/TLSValidate/SSL\");'");
                }
                htw.Write(HtmlTextWriter.TagRightChar);
                htw.Write("  {0} is Not Approved - please remove</p>", M.VersionString(v));
                htw.WriteEndTag("a");
                htw.WriteEndTag("p");
                protocolCount = protocolCount + 1;

                if (suites.Keys.Count == protocolCount)
                {
                    htw.WriteBeginTag("p");
                    htw.Write(HtmlTextWriter.TagRightChar);
                    w.WriteLine("  Please add at least one approved SSL/TLS protocol");
                    htw.WriteEndTag("p");
                }
            }
            else
            {
                htw.WriteBeginTag("p");
                htw.Write(HtmlTextWriter.TagRightChar);
                htw.Write("  Testing on {0}:", M.VersionString(v));
                htw.WriteEndTag("p");

                SupportedCipherSuites scs = suites[v];
                htw.WriteLine();
                htw.WriteLine();

                if (!(scs.PrefServer))
                {
                    htw.WriteBeginTag("p");
                    htw.Write(HtmlTextWriter.TagRightChar);
                    htw.Write("  Server Selection: Not Approved");
                    if (scs.PrefClient)
                    {
                        htw.WriteLine("  - Uses client preferences - Needs to support server preferences");
                    }
                    else
                    {
                        htw.WriteLine("  - uses complex preferences - Needs to support server preferences");
                    }
                    htw.WriteLine();
                    htw.WriteEndTag("p");
                }

                List<String> notApproved = new List<String>();
                List<String> approved = new List<String>();

                if (String.Compare(M.VersionString(v), "TLSv1.0") != 0)
                {
                    bool correctOrdering = true;

                    foreach (int s in scs.Suites)
                    {

                        String cipher = CipherSuite.ToName(s);
                        if (cipher.Contains("APPROVED"))
                        {
                            approved.Add(cipher.Substring(0, cipher.Length - 9));
                        }
                        else
                        {
                            correctOrdering = false;
                            notApproved.Add(cipher);
                        }

                    }

                    List<String> temp = cipherOrdering(approved);
                    if (correctOrdering)
                    {
                        for (int i = 0; i < temp.Count; i++)
                        {
                            if (!(temp[i].Equals(approved[i])))
                            {
                                correctOrdering = false;
                            }
                        }
                    }

                    if (correctOrdering)
                    {
                        htw.WriteBeginTag("p");
                        htw.Write(HtmlTextWriter.TagRightChar);
                        htw.WriteLine("  Cipher Ordering Approved");
                        htw.WriteEndTag("p");
                    }
                    else
                    {
                        approved = cipherOrdering(approved);
                        if (approved.Count > 0)
                        {
                            htw.WriteBeginTag("p");
                            htw.Write(HtmlTextWriter.TagRightChar);
                            htw.WriteLine("  Cipher Ordering Not Approved");
                            htw.WriteEndTag("p");
                            htw.WriteBeginTag("p");
                            htw.Write(HtmlTextWriter.TagRightChar);
                            htw.WriteLine("  Here is the recommended ordering");
                            htw.WriteEndTag("p");

                            htw.WriteBeginTag("ol");
                            htw.Write(HtmlTextWriter.TagRightChar);
                            foreach (String s in approved)
                            {
                                htw.WriteBeginTag("li");
                                htw.Write(HtmlTextWriter.TagRightChar);
                                htw.WriteLine("     {0}", s);
                                htw.WriteEndTag("li");
                            }
                            htw.WriteEndTag("ol");
                        }
                        else
                        {
                            htw.WriteBeginTag("p");
                            htw.Write(HtmlTextWriter.TagRightChar);
                            htw.Write("Please add at least one approved CipherSuite");
                            htw.WriteEndTag("p");
                        }

                        if (notApproved.Count > 0)
                        {
                            htw.WriteBeginTag("p");
                            htw.Write(HtmlTextWriter.TagRightChar);
                            htw.WriteLine("  Remove these ciphers - Not Approved");
                            htw.WriteEndTag("p");

                            // htw.WriteBeginTag("script");
                            // htw.Write(" type='text/javascript'");
                            // htw.Write(HtmlTextWriter.TagRightChar);
                            // htw.WriteLine("function newPopup(url) {");
                            // htw.WriteLine("popupWindow = window.open(");
                            // htw.WriteLine("url,'popUpWindow'," +
                            //     "'height=500,width=500,left=10,top=10,resizable=yes," +
                            //     "scrollbars=yes,toolbar=yes,menubar=no,location=no," +
                            //     "directories=no,status=yes')}");
                            // htw.WriteEndTag("script");
                            foreach (String s in notApproved)
                            {
                                htw.WriteBeginTag("p");
                                htw.Write(HtmlTextWriter.TagRightChar);
                                htw.WriteBeginTag("a");
                                htw.Write(" href=");
                                if (s.Contains("RC4"))
                                {
                                    htw.Write(" 'JavaScript: newPopup(\"/TLSValidate/RC4\");'");
                                }
                                else if (s.Contains("3DES"))
                                {
                                    htw.Write(" 'JavaScript: newPopup(\"/TLSValidate/threeDES\");'");
                                }
                                else if(s.Contains("AES"))
                                {
                                  htw.Write(" 'JavaScript: newPopup(\"/TLSValidate/AES\");'");
                                }
                                else
                                {
                                    htw.Write(" 'JavaScript: newPopup(\"/TLSValidate/other\");'");
                                }
                                htw.Write(HtmlTextWriter.TagRightChar);
                                htw.WriteLine("     {0}", s);
                                htw.WriteEndTag("a");
                                htw.WriteEndTag("p");
                            }
                            htw.WriteEndTag("ul");
                        }



                    }
                    approved.Clear();
                    notApproved.Clear();
                    htw.WriteLine();
                }
            }

        }
        htw.WriteBeginTag("p");
        htw.Write(HtmlTextWriter.TagRightChar);
        if(minDHSize<2048 && minDHSize>0){
          htw.WriteBeginTag("p");
          htw.Write(HtmlTextWriter.TagRightChar);
          htw.Write("DH size is {0}", minDHSize);
          htw.Write(" Please make your DH size at least 2048");
          htw.WriteEndTag("p");
        }
        htw.WriteLine("=========================================");
        htw.WriteEndTag("p");
        if (ssl2Chain != null)
        {
            if (checkKeySize(ssl2Chain, 0))
            {
                htw.WriteBeginTag("p");
                htw.Write(HtmlTextWriter.TagRightChar);
                htw.WriteLine("+++++ SSLv2 certificate - Not Approved");
                htw.WriteEndTag("p");

                htw.WriteBeginTag("p");
                htw.Write(HtmlTextWriter.TagRightChar);
                PrintCertHtml(htw, ssl2Chain, 0);
                htw.WriteEndTag("p");
            }
        }

        String chainCount = "+++++ SSLv3/TLS: certificate chain(s) - Not Approved";
        foreach (X509Chain xchain in chains.Values)
        {
            int n = xchain.Elements.Length;
            for (int i = 0; i < n; i++)
            {
                bool flag = true;
                if (checkKeySize(xchain, i))
                {
                    if (flag)
                    {
                        htw.WriteBeginTag("p");
                        htw.Write(HtmlTextWriter.TagRightChar);
                        htw.WriteLine(chainCount);
                        htw.WriteEndTag("p");
                        flag = false;
                    }
                    htw.WriteBeginTag("p");
                    htw.Write(HtmlTextWriter.TagRightChar);
                    PrintCertHtml(htw, xchain, i);
                    htw.WriteEndTag("p");
                }
            }
        }

        htw.WriteEndTag("body");
        htw.WriteEndTag("html");
    }



    /*
    * Encode the report as JSON.
    */
    internal void Print(JSON js)
    {
      bool pass = true;
      js.OpenInit(false);
      js.AddPair("connectionName", connName);
      js.AddPair("connectionPort", connPort);
      js.AddPair("SNI", sni);
      if (ssl2Suites != null && ssl2Suites.Length > 0)
      {
        pass = false;
        js.OpenPairObject("SSLv2");
        js.AddPair("approvalStatus", "notApproved");
        js.Close();
      }


      foreach (int v in suites.Keys)
      {
        js.OpenPairObject(M.VersionString(v));
        SupportedCipherSuites scs = suites[v];
        string sel;
        if (scs.PrefClient)
        {
          pass = false;
          sel = "client - Not Approved";
        }
        else if (scs.PrefServer)
        {
          sel = "server";
        }
        else
        {
          pass = false;
          sel = "complex - Not Approved";
        }
        js.AddPair("suiteSelection", sel);

        List<String> approved = new List<String>();
        List<String> notApproved = new List<String>();
        bool ordering = true;

        foreach (int s in scs.Suites)
        {
          String cipher = CipherSuite.ToName(s);
          if (cipher.Contains("APPROVED"))
          {
            approved.Add(cipher.Substring(0, cipher.Length - 9));
          }
          else
          {
            notApproved.Add(cipher);
            ordering = false;
          }
        }
        List<String> properOrdering = cipherOrdering(approved);
        if(ordering)
        {
          for(int i=0;i<approved.Count;i++)
          {
            if(ordering == false)
            {
              break;
            }
            if(!(properOrdering[i].Equals(approved[i])))
            {
              ordering = false;
            }

          }
        }
        js.AddPair("CorrectOrdering", ordering);
        if(!ordering)
        {
          pass = false;
          js.OpenPairArray("ProperCipherOrdering");
          foreach(String s in properOrdering)
          {
            js.AddElement(s);
          }
          js.Close();
          js.OpenPairArray("NotApprovedCiphers");
          foreach(String s in notApproved)
          {
            js.AddElement(s);
          }
          js.Close();
        }
            js.Close();
      }

      if (ssl2Chain != null)
      {
        pass = false;
        js.OpenPairObject("ssl2Cert");
        PrintCert(js, ssl2Chain, 0, pass);
        js.Close();
      }

      js.OpenPairObject("certificates");
      foreach (X509Chain xchain in chains.Values)
      {
        int n = xchain.Elements.Length;
        for (int i = 0; i < n; i++)
        {
          PrintCert(js, xchain, i, pass);
          js.Close();
        }
      }
      if (minDHSize > 0)
      {
        js.AddPair("minDHSize", minDHSize);
      }

      if(pass){
        js.AddPair("Status", "SCAN_APPROVED");
      }
      else{
        js.AddPair("Status", "SCAN_FAILED");
      }
      js.Close();
    }

    /*
    * Add certificate to output. The caller is responsible for
    * opening the certificate object.
    */
    void PrintCert(JSON js, X509Chain xchain, int num, bool pass)
    {
      js.OpenPairObject("thumbprint:"+xchain.ThumbprintsRev[num]);
      //js.AddPair("thumbprint", xchain.ThumbprintsRev[num]);
      X509Cert xc = xchain.ElementsRev[num];
      if (xc == null)
      {
        js.AddPair("decodeError",
        xchain.DecodingIssuesRev[num]);
        pass = false;
      }
      else
      {
        if (xc.KeyType.Contains("EC") && xc.KeySize < 256)
        {
          js.AddPair("Size", "Less than 256 not approved");
          pass = false;
        }
        else if (xc.KeyType.Contains("DSA") && xc.KeySize < 1024)
        {
          js.AddPair("Size", "Less than 1024 not approved");
          pass = false;
        }
        else if (xc.KeyType.Contains("RSA") && (xc.KeySize<2048))
        {
          js.AddPair("Size", "Less than 2048 not approved");
          pass = false;
        }
        else
        {
          js.AddPair("Size", "Approved");
        }

        js.AddPair("keyType", xc.KeyType);
        js.AddPair("keySize", xc.KeySize);
      }
    }
  }
