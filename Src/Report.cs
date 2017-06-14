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

class Report {


	/*
	 * Connection name (server name).
	 */
	internal string ConnName {
		get {
			return connName;
		}
		set {
			connName = value;
		}
	}

	/*
	 * Connection port.
	 */
	internal int ConnPort {
		get {
			return connPort;
		}
		set {
			connPort = value;
		}
	}

	/*
	 * Server name sent in the SNI extension. This may be null if
	 * no SNI extension was sent.
	 */
	internal string SNI {
		get {
			return sni;
		}
		set {
			sni = value;
		}
	}

	/*
	 * List of supported SSLv2 cipher suites, in the order returned
	 * by the server (which is purely advisory, since selection is
	 * done by the client). It is null if SSLv2 is not supported.
	 */
	internal int[] SSLv2CipherSuites {
		get {
			return ssl2Suites;
		}
		set {
			ssl2Suites = value;
		}
	}

	/*
	 * Certificate sent by the server if SSLv2 is supported (null
	 * otherwise). It is reported as a chain of length 1.
	 */
	internal X509Chain SSLv2Chain {
		get {
			return ssl2Chain;
		}
	}

	/*
	 * List of supported cipher suites, indexed by protocol version.
	 * This map contains information for version SSL 3.0 and more.
	 */
	internal IDictionary<int, SupportedCipherSuites> CipherSuites {
		get {
			return suites;
		}
	}

	/*
	 * Support for SSLv3+ with a SSLv2 ClientHello format.
	 */
	internal bool SupportsV2Hello {
		get {
			return helloV2;
		}
		set {
			helloV2 = value;
		}
	}

	/*
	 * Set to true if we had to shorten our ClientHello messages
	 * (this indicates a server with a fixed, small buffer for
	 * incoming ClientHello).
	 */
	internal bool NeedsShortHello {
		get {
			return shortHello;
		}
		set {
			shortHello = value;
		}
	}

	/*
	 * Set to true if we had to suppress extensions from our
	 * ClientHello (flawed server that does not support extensions).
	 */
	internal bool NoExtensions {
		get {
			return noExts;
		}
		set {
			noExts = value;
		}
	}

	/*
	 * Set to true if the server, at some point, agreed to use
	 * Deflate compression.
	 */
	internal bool DeflateCompress {
		get {
			return compress;
		}
		set {
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
	internal bool SupportsSecureRenegotiation {
		get {
			return doesRenego;
		}
		set {
			doesRenego = value;
		}
	}

	/*
	 * Set to true if the server appears to support the Encrypt-then-MAC
	 * extension (RFC 7366). This is only about the extension, _not_
	 * cipher suites that are "natively" in Encrypt-then-MAC mode (e.g.
	 * AES/GCM and ChaCha20+Poly1305 cipher suites).
	 */
	internal bool SupportsEncryptThenMAC {
		get {
			return doesEtM;
		}
		set {
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
	internal long ServerTimeOffset {
		get {
			return serverTimeOffset;
		}
		set {
			serverTimeOffset = value;
		}
	}

	/*
	 * Minimal size (in bits) of DH parameters sent by server. If
	 * server never used DHE or SRP, then this is 0.
	 */
	internal int MinDHSize {
		get {
			return minDHSize;
		}
		set {
			minDHSize = value;
		}
	}

	/*
	 * Minimal size (in bits) of ECDH parameters sent by server. If
	 * server never used ECDHE, then this is 0. This value is for
	 * handshakes where the client DID NOT send a "supported curve"
	 * extension.
	 */
	internal int MinECSize {
		get {
			return minECSize;
		}
		set {
			minECSize = value;
		}
	}

	/*
	 * Minimal size (in bits) of ECDH parameters sent by server. If
	 * server never used ECDHE, then this is 0. This value is for
	 * handshakes where the client sent a "supported curve" extension.
	 */
	internal int MinECSizeExt {
		get {
			return minECSizeExt;
		}
		set {
			minECSizeExt = value;
		}
	}

	/*
	 * Named curves used by the server for ECDH parameters.
	 */
	internal SSLCurve[] NamedCurves {
		get {
			return namedCurves;
		}
		set {
			namedCurves = value;
		}
	}

	/*
	 * List of EC suites that the server supports when the client
	 * does not send a Supported Elliptic Curves extension. The
	 * list is not in any specific order.
	 */
	internal int[] SpontaneousEC {
		get {
			return spontaneousEC;
		}
		set {
			spontaneousEC = value;
		}
	}

	/*
	 * Named curves spontaneously used by the server for ECDH
	 * parameters. These are the curves that the server elected to
	 * use in the absence of a "supported elliptic curves" extension
	 * from the client.
	 */
	internal SSLCurve[] SpontaneousNamedCurves {
		get {
			return spontaneousNamedCurves;
		}
		set {
			spontaneousNamedCurves = value;
		}
	}

	/*
	 * If non-zero, then this is the size of the "explicit prime"
	 * curve selected by the server.
	 */
	internal int CurveExplicitPrime {
		get {
			return curveExplicitPrime;
		}
		set {
			curveExplicitPrime = value;
		}
	}

	/*
	 * If non-zero, then this is the size of the "explicit char2"
	 * curve selected by the server.
	 */
	internal int CurveExplicitChar2 {
		get {
			return curveExplicitChar2;
		}
		set {
			curveExplicitChar2 = value;
		}
	}

	/*
	 * Set to true if the server was detected to reuse DH parameters
	 * (for DHE or DH_anon).
	 */
	internal bool KXReuseDH {
		get {
			return kxReuseDH;
		}
		set {
			kxReuseDH = value;
		}
	}

	/*
	 * Set to true if the server was detected to reuse ECDH parameters
	 * (for ECDHE or ECDH_anon).
	 */
	internal bool KXReuseECDH {
		get {
			return kxReuseECDH;
		}
		set {
			kxReuseECDH = value;
		}
	}

	/*
	 * Set to true if one ServerKeyExchange message (at least) could
	 * not be fully decoded.
	 */
	internal bool UnknownSKE {
		get {
			return unknownSKE;
		}
		set {
			unknownSKE = value;
		}
	}

	/*
	 * Get all certificate chains gathered so far.
	 */
	internal X509Chain[] AllChains {
		get {
			return M.ToValueArray(chains);
		}
	}

	/*
	 * If true, then the report will include the whole certificates
	 * sent by the server (PEM format).
	 */
	internal bool ShowCertPEM {
		get {
			return withPEM;
		}
		set {
			withPEM = value;
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
	int minECSize;
	int minECSizeExt;
	SSLCurve[] namedCurves;
	int[] spontaneousEC;
	SSLCurve[] spontaneousNamedCurves;
	int curveExplicitPrime;
	int curveExplicitChar2;
	bool kxReuseDH;
	bool kxReuseECDH;
	bool unknownSKE;
	bool withPEM;

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
		if (ssl2Cert == null) {
			ssl2Chain = null;
		} else {
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
		if (sni == null) {
			w.WriteLine("No SNI sent");
		} else {
			w.WriteLine("SNI: {0}", sni);
		}
		if (ssl2Suites != null && ssl2Suites.Length > 0) {
			w.WriteLine("  {0}", M.VersionString(M.SSLv20));
			foreach (int s in ssl2Suites) {
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

                if(suites.Keys.Count == protocolCount)
                {
                    w.WriteLine("  Please add at least one approved SSL/TSL protocol");
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
                        for (int i = 0; i < temp.Count;i++)
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
        if(minDHSize < 2048 && minDHSize > 0)
        {
            w.WriteLine("DH size is {0}", minDHSize);
            w.WriteLine("DH should be 2048 or above.");

        }
		if (ssl2Chain != null) {
            if (checkKeySize(ssl2Chain,0))
            {
                w.WriteLine("+++++ SSLv2 certificate - Not Approved");
                PrintCert(w, ssl2Chain, 0);
            }
		}

		String chainCount = "+++++ SSLv3/TLS: certificate chain(s) - Not Approved";
		foreach (X509Chain xchain in chains.Values) {
			int n = xchain.Elements.Length;
			for (int i = 0; i < n; i ++) {
                bool flag = true;
                if (checkKeySize(xchain, i))
                {
                    if (flag)
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

		if (xc == null) {
            w.WriteLine("thumprint:  {0}", xchain.ThumbprintsRev[num]);
            w.WriteLine("UNDECODABLE: {0}",
				xchain.DecodingIssuesRev[num]);
		} else {
            if (xc.KeySize < 2048)
            {
                if(xc.KeyType.Contains("EC") && xc.KeySize < 256)
                {
                    w.WriteLine("Key size should be 256 or larger for {0}", xc.KeyType);
                }
                else if(xc.KeyType.Contains("DSA") && xc.KeySize < 1024)
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
            w.WriteBeginTag("li");
            w.Write(HtmlTextWriter.TagRightChar);
            w.WriteBeginTag("ul");
            w.Write(HtmlTextWriter.TagRightChar);
            w.WriteLine("UNDECODABLE: {0}",
                xchain.DecodingIssuesRev[num]);
            w.WriteEndTag("ul");
            w.WriteEndTag("li");
        }
        else
        {
            if (xc.KeySize < 2048)
            {
                w.WriteBeginTag("p");
                w.Write(HtmlTextWriter.TagRightChar);
                w.WriteLine("thumprint:  {0}", xchain.ThumbprintsRev[num]);
                w.WriteEndTag("p");

                w.WriteBeginTag("ul");
                w.Write(HtmlTextWriter.TagRightChar);
                w.WriteBeginTag("li");
                w.Write(HtmlTextWriter.TagRightChar);
                w.WriteLine("key size is Invalid:   {0}", xc.KeySize);
                w.WriteEndTag("li");
                w.WriteBeginTag("li");
                w.Write(HtmlTextWriter.TagRightChar);
                w.WriteLine("Key size should be 2048 or larger");
                w.WriteEndTag("li");
                w.WriteEndTag("ul");
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

        AES = GCMOrdering(AES);
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

        GCMs = ECOrdering(GCMs);
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

        ec = EphemOrdering(ec);
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

        ephem = DHOrdering(ephem);
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

        dh.AddRange(noDh);

        return dh;
   
    }

    /*
     * the 'has' functions check for each cipher,
     * created to make code more readable
     */
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
        htw.WriteBeginTag("html");
        htw.Write(HtmlTextWriter.TagRightChar);

        htw.WriteBeginTag("head");
        htw.Write(HtmlTextWriter.TagRightChar);
        htw.Write("Connection: {0}:{1}", connName, connPort);
        htw.WriteEndTag("head");
        htw.WriteBeginTag("body");
        htw.Write(HtmlTextWriter.TagRightChar);

        if (ssl2Suites != null && ssl2Suites.Length > 0)
        {
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
            htw.WriteBeginTag("p");
            htw.Write(HtmlTextWriter.TagRightChar);
            htw.WriteBeginTag("a");
            htw.Write(" href=");
            htw.Write(" 'JavaScript: newPopup(\"htmlPages/BrokenProtocols/SSLv2.html\");'");
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
                htw.WriteBeginTag("p");
                htw.Write(HtmlTextWriter.TagRightChar);
                htw.WriteBeginTag("a");
                htw.Write(" href=");
                if (String.Compare(M.VersionString(v), "TLSv1.0") == 0)
                {
                    htw.Write(" 'JavaScript: newPopup(\"htmlPages/BrokenProtocols/TLS1.html\");'");
                }
                else
                {
                    htw.Write(" 'JavaScript: newPopup(\"htmlPages/BrokenProtocols/SSLv3.html\");'");
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
                    w.WriteLine("  Please add at least one approved SSL/TSL protocol");
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
                                htw.WriteBeginTag("ul");
                                htw.Write(HtmlTextWriter.TagRightChar);
                                foreach (String s in notApproved)
                                {
                                    htw.WriteBeginTag("li");
                                    htw.Write(HtmlTextWriter.TagRightChar);
                                    htw.WriteBeginTag("a");
                                    htw.Write(" href=");
                                    if (s.Contains("RC4"))
                                    {
                                        htw.Write(" 'JavaScript: newPopup(\"htmlPages/BrokenCiphers/RC4.html\");'");
                                    }
                                    else if (s.Contains("3DES"))
                                    {
                                        htw.Write(" 'JavaScript: newPopup(\"htmlPages/BrokenCiphers/3DES.html\");'");
                                    }
                                    else
                                    {
                                        htw.Write(" 'JavaScript: newPopup(\"htmlPages/BrokenCiphers/Other.html\");'");
                                    }
                                    htw.Write(HtmlTextWriter.TagRightChar);
                                    htw.WriteBeginTag("p");
                                    htw.Write(HtmlTextWriter.TagRightChar);
                                    htw.WriteLine("     {0}", s);
                                    htw.WriteEndTag("p");
                                    htw.WriteEndTag("a");
                                    htw.WriteEndTag("li");
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
		js.OpenInit(false);
		js.AddPair("connectionName", connName);
		js.AddPair("connectionPort", connPort);
		js.AddPair("SNI", sni);
		if (ssl2Suites != null && ssl2Suites.Length > 0) {
			js.OpenPairObject("SSLv2");
			js.OpenPairArray("suites");
			foreach (int s in ssl2Suites) {
				js.OpenElementObject();
				js.AddPair("id", s);
				js.AddPair("name", CipherSuite.ToNameV2(s));
				js.Close();
			}
			js.Close();
			js.Close();
		}

		foreach (int v in suites.Keys) {
			js.OpenPairObject(M.VersionString(v));
			SupportedCipherSuites scs = suites[v];
			string sel;
			if (scs.PrefClient) {
				sel = "client";
			} else if (scs.PrefServer) {
				sel = "server";
			} else {
				sel = "complex";
			}
			js.AddPair("suiteSelection", sel);
			js.OpenPairArray("suites");
			foreach (int s in scs.Suites) {
				js.OpenElementObject();
				js.AddPair("id", s);
				js.AddPair("name", CipherSuite.ToName(s));
				CipherSuite cs;
				if (CipherSuite.ALL.TryGetValue(s, out cs)) {
					js.AddPair("strength", cs.Strength);
					js.AddPair("forwardSecrecy",
						cs.HasForwardSecrecy);
					js.AddPair("anonymous",
						cs.IsAnonymous);
					js.AddPair("serverKeyType",
						cs.ServerKeyType);
				}
				js.Close();
			}
			js.Close();
			js.Close();
		}

		if (ssl2Chain != null) {
			js.OpenPairObject("ssl2Cert");
			PrintCert(js, ssl2Chain, 0);
			js.Close();
		}

		js.OpenPairArray("ssl3Chains");
		foreach (X509Chain xchain in chains.Values) {
			js.OpenElementObject();
			int n = xchain.Elements.Length;
			js.AddPair("length", n);
			js.AddPair("decoded", xchain.Decodable);
			if (xchain.Decodable) {
				js.AddPair("namesMatch", xchain.NamesMatch);
				js.AddPair("includesRoot", xchain.IncludesRoot);
				js.OpenPairArray("signHashes");
				foreach (string name in xchain.SignHashes) {
					js.AddElement(name);
				}
				js.Close();
			}
			js.OpenPairArray("certificates");
			for (int i = 0; i < n; i ++) {
				js.OpenElementObject();
				PrintCert(js, xchain, i);
				js.Close();
			}
			js.Close();
			js.Close();
		}
		js.Close();

		js.AddPair("deflateCompress", DeflateCompress);
		if (serverTimeOffset == Int64.MinValue) {
			js.AddPair("serverTime", "none");
		} else if (serverTimeOffset == Int64.MaxValue) {
			js.AddPair("serverTime", "random");
		} else {
			DateTime dt = DateTime.UtcNow;
			dt = dt.AddMilliseconds((double)serverTimeOffset);
			js.AddPair("serverTime", string.Format(
				"{0:yyyy-MM-dd HH:mm:ss} UTC", dt));
			js.AddPair("serverTimeOffsetMillis",
				serverTimeOffset);
		}
		js.AddPair("secureRenegotiation", doesRenego);
		js.AddPair("rfc7366EtM", doesEtM);
		js.AddPair("ssl2HelloFormat", helloV2);
		if (minDHSize > 0) {
			js.AddPair("minDHSize", minDHSize);
			js.AddPair("kxReuseDH", kxReuseDH);
		}
		if (minECSize > 0) {
			js.AddPair("minECSize", minECSize);
		}
		if (minECSizeExt > 0) {
			js.AddPair("minECSizeExt", minECSizeExt);
		}
		if (minECSize > 0 || minECSizeExt > 0) {
			js.AddPair("kxReuseECDH", kxReuseECDH);
		}

		if ((namedCurves != null && namedCurves.Length > 0)
			|| curveExplicitPrime > 0 || curveExplicitChar2 > 0)
		{
			js.OpenPairArray("namedCurves");
			foreach (SSLCurve nc in namedCurves) {
				js.OpenElementObject();
				js.AddPair("name", nc.Name);
				js.AddPair("size", nc.Size);
				js.Close();
			}
			if (curveExplicitPrime > 0) {
				js.OpenElementObject();
				js.AddPair("name", "explicitPrime");
				js.AddPair("size", curveExplicitPrime);
				js.Close();
			}
			if (curveExplicitChar2 > 0) {
				js.OpenElementObject();
				js.AddPair("name", "explicitChar2");
				js.AddPair("size", curveExplicitChar2);
				js.Close();
			}
			js.Close();
		}

		js.Close();
		js.Close();
	}

	/*
	 * Add certificate to output. The caller is responsible for
	 * opening the certificate object.
	 */
	void PrintCert(JSON js, X509Chain xchain, int num)
	{
		js.AddPair("thumbprint", xchain.ThumbprintsRev[num]);
		X509Cert xc = xchain.ElementsRev[num];
		js.AddPair("decodable", xc != null);
		if (xc == null) {
			js.AddPair("decodeError",
				xchain.DecodingIssuesRev[num]);
		} else {
			js.AddPair("serialHex", xc.SerialHex);
			js.AddPair("subject", xc.Subject.ToString());
			js.AddPair("issuer", xc.Issuer.ToString());
			js.AddPair("validFrom", string.Format(
				"{0:yyyy-MM-dd HH:mm:ss} UTC", xc.ValidFrom));
			js.AddPair("validTo", string.Format(
				"{0:yyyy-MM-dd HH:mm:ss} UTC", xc.ValidTo));
			js.AddPair("keyType", xc.KeyType);
			js.AddPair("keySize", xc.KeySize);
			string cname = xc.CurveName;
			if (cname != null) {
				js.AddPair("keyCurve", cname);
			}
			js.AddPair("signHash", xc.HashAlgorithm);
			js.AddPair("selfIssued", xc.SelfIssued);
			if (num == 0) {
				js.OpenPairArray("serverNames");
				foreach (string name in xc.ServerNames) {
					js.AddElement(name);
				}
				js.Close();
			}
		}
		if (withPEM) {
			js.AddPair("PEM",
				M.ToPEM("CERTIFICATE", xchain.EncodedRev[num]));
		}
	}
}
