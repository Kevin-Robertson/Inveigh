/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2025, Kevin Robertson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
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
using System.Collections;
using System.Collections.Generic;

namespace Quiddity
{
    class HTTPListener
    {
        public bool EnabledWebDAV { get; set; }
        public string Cert { get; set; }
        public string CertPassword { get; set; }
        public string[] IgnoreAgents { get; set; }
        public string HTTPAuth { get; set; }
        public string WebDAVAuth { get; set; }
        public string WPADAuth { get; set; }
        public string HTTPRealm { get; set; }
        public string HTTPResponse { get; set; }
        public string WPADResponse { get; set; }
        public string Challenge { get; set; }
        public string NetbiosDomain { get; set; }
        public string ComputerName { get; set; }
        public string DNSDomain { get; set; }

        public static bool isRunning = false;
        public const SslProtocols tls12 = (SslProtocols)0x00000C00;
        public static Hashtable httpSessionTable = Hashtable.Synchronized(new Hashtable());
        public static Hashtable tcpSessionTable = Hashtable.Synchronized(new Hashtable());

        public HTTPListener()
        {
            this.EnabledWebDAV = true;
            this.IgnoreAgents = new string[] {"Firefox"};
            this.HTTPAuth = "NTLM";
            this.WebDAVAuth = "NTLM";
            this.WPADAuth = "NTLM";
            this.HTTPRealm = "temp";
            this.NetbiosDomain = "temp";
            this.ComputerName = "temp";
            this.DNSDomain = "temp";
        }

        internal void Start(IPAddress ipAddress, int port, string type)
        {
            TCPListener tcpListener = new TCPListener(ipAddress, port);
            IAsyncResult tcpAsync;

            try
            {
                tcpListener.Start();
                isRunning = true;

                if (type.Equals("Proxy"))
                {
                    tcpListener.Server.LingerState = new LingerOption(true, 0);
                }

                if (tcpListener.Server.IsBound)
                {

                    while (isRunning)
                    {

                        try
                        {
                            tcpAsync = tcpListener.BeginAcceptTcpClient(null, null);

                            do
                            {
                                Thread.Sleep(10);

                                if (!isRunning)
                                {
                                    break;
                                }

                            }
                            while (!tcpAsync.IsCompleted);

                            if (isRunning)
                            {
                                TcpClient tcpClient = tcpListener.EndAcceptTcpClient(tcpAsync);
                                string sourceIP = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Address.ToString();

                                if (type.Equals("Proxy") && tcpSessionTable.ContainsKey(sourceIP) && DateTime.Compare((DateTime)tcpSessionTable[sourceIP], DateTime.Now) > 0)
                                {
                                    tcpClient.Client.Close();
                                }
                                else
                                {
                                    object[] parameters = { tcpClient, type, port };
                                    ThreadPool.QueueUserWorkItem(new WaitCallback(ReceiveClient), parameters);
                                }

                            }

                        }
                        catch (Exception ex)
                        {
                            OutputError(ex, type, port);
                        }

                    }

                }

            }
            catch (Exception ex)
            {
                OutputError(ex, type, port);
            }

        }

        internal void ReceiveClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            TcpClient tcpClient = (TcpClient)parameterArray[0];
            string type = (string)parameterArray[1];
            int port = (int)parameterArray[2];

            try
            {
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
                    byte[] certificateData = Convert.FromBase64String(Cert);
                    certificate = new X509Certificate2(certificateData, CertPassword, X509KeyStorageFlags.MachineKeySet);
                    tcpStream = tcpClient.GetStream();
                    httpsStream = new SslStream(tcpStream, false);
                }
                else
                {
                    httpStream = tcpClient.GetStream();
                }

                while (tcpClient.Connected && isRunning)
                {
                    byte[] requestData = new byte[16384];

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

                            if (!ex.Message.Contains("A call to SSPI failed, see inner exception.")) // todo check
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
                        OutputRequestMethod(type, listenerPort, sourceIP, sourcePort, request.URI, request.Method);
                    }

                    if (!string.IsNullOrEmpty(request.URI))
                    {
                        OutputHostHeader(type, listenerPort, sourceIP, sourcePort, request.Host);
                    }

                    if (!string.IsNullOrEmpty(request.UserAgent))
                    {
                        OutputUserAgent(type, listenerPort, sourceIP, sourcePort, request.UserAgent);
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

                        if (!Utilities.ArrayIsNullOrEmpty(IgnoreAgents) && WPADAuth.Equals("NTLM"))
                        {

                            foreach (string agent in IgnoreAgents)
                            {

                                if (request.UserAgent.ToUpper().Contains(agent.ToUpper()))
                                {
                                    wpadAuthIgnoreMatch = true;
                                }

                            }

                            if (wpadAuthIgnoreMatch)
                            {
                                OutputIgnore(type, listenerPort, sourceIP, sourcePort, "switching wpad.dat auth to anonymous due to user agent match"); // todo make better
                            }

                        }

                        if (type.Equals("Proxy"))
                        {
                            response.StatusCode = "407";
                            response.ProxyAuthenticate = "NTLM";
                            response.WWWAuthenticate = "";
                            response.Connection = "close";
                        }
                        else if (EnabledWebDAV && request.Method.Equals("PROPFIND") && WebDAVAuth.StartsWith("NTLM"))
                        {
                            response.WWWAuthenticate = "NTLM";
                        }
                        else if (EnabledWebDAV && request.Method.Equals("PROPFIND") && WebDAVAuth.Equals("BASIC"))
                        {
                            response.WWWAuthenticate = string.Concat("Basic realm=", HTTPRealm);
                        }
                        else if (!string.Equals(request.URI, "/wpad.dat") && string.Equals(HTTPAuth, "ANONYMOUS") || string.Equals(request.URI, "/wpad.dat") && string.Equals(WPADAuth, "ANONYMOUS") || wpadAuthIgnoreMatch ||
                            (EnabledWebDAV && request.Method.Equals("OPTIONS")))
                        {
                            response.StatusCode = "200";
                            response.ReasonPhrase = "OK";
                        }
                        else if ((HTTPAuth.StartsWith("NTLM") && !string.Equals(request.URI, "/wpad.dat")) || (WPADAuth.StartsWith("NTLM") && string.Equals(request.URI, "/wpad.dat")))
                        {
                            response.WWWAuthenticate = "NTLM";
                        }
                        else if ((string.Equals(HTTPAuth, "BASIC") && !string.Equals(request.URI, "/wpad.dat")) || (string.Equals(WPADAuth, "BASIC") && string.Equals(request.URI, "/wpad.dat")))
                        {
                            response.WWWAuthenticate = string.Concat("Basic realm=", HTTPRealm);
                        }

                        if (!string.IsNullOrEmpty(request.Authorization) && (request.Authorization.ToUpper().StartsWith("NTLM ") || request.Authorization.ToUpper().StartsWith("NEGOTIATE ")) || (!string.IsNullOrEmpty(request.ProxyAuthorization) && request.ProxyAuthorization.ToUpper().StartsWith("NTLM ")))
                        {
                            string authorization = request.Authorization;
 
                            if (!string.IsNullOrEmpty(request.ProxyAuthorization))
                            {
                                authorization = request.ProxyAuthorization;
                            }

                            NTLMNegotiate ntlm = new NTLMNegotiate();
                            ntlm.ReadBytes(Convert.FromBase64String(authorization.Split(' ')[1]), 0);

                            if (ntlm.MessageType == 1)
                            {
                                byte[] timestamp = BitConverter.GetBytes(DateTime.Now.ToFileTime());
                                NTLMChallenge challenge = new NTLMChallenge(Challenge, NetbiosDomain, ComputerName, DNSDomain, ComputerName, DNSDomain, timestamp);
                                byte[] challengeData = challenge.GetBytes(ComputerName);
                                ntlmChallenge = BitConverter.ToString(challenge.ServerChallenge).Replace("-", "");
                                string sessionTimestamp = BitConverter.ToString(timestamp).Replace("-", "");
                                httpSessionTable[sessionTimestamp] = ntlmChallenge;
                                OutputChallenge(type, listenerPort, sourceIP, sourcePort, ntlmChallenge);

                                if (String.Equals(type, "Proxy"))
                                {
                                    response.StatusCode = "407";
                                    response.ProxyAuthenticate = "NTLM " + Convert.ToBase64String(challengeData);
                                }
                                else
                                {

                                    if (request.Authorization.ToUpper().StartsWith("NEGOTIATE "))
                                    {
                                        response.WWWAuthenticate = "Negotiate " + Convert.ToBase64String(challengeData);
                                    }
                                    else
                                    {
                                        response.WWWAuthenticate = "NTLM " + Convert.ToBase64String(challengeData);
                                    }

                                }

                                response.Connection = "";
                            }
                            else if (ntlm.MessageType == 3)
                            {
                                response.StatusCode = "200";
                                response.ReasonPhrase = "OK";
                                ntlmStage = 3;
                                isClientClose = true;
                                NTLMResponse ntlmResponse = new NTLMResponse(Convert.FromBase64String(authorization.Split(' ')[1]), false);
                                string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                                string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                                string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                                string ntlmResponseHash = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-", "");
                                string lmResponseHash = BitConverter.ToString(ntlmResponse.LmChallengeResponse).Replace("-", "");

                                if (string.IsNullOrEmpty(ntlmChallenge)) // NTLMv2 workaround to track sessions over different ports without a cookie
                                {

                                    try
                                    {
                                        byte[] timestamp = new byte[8];                                 
                                        Buffer.BlockCopy(ntlmResponse.NtChallengeResponse, 24, timestamp, 0, 8);
                                        string sessionTimestamp = BitConverter.ToString(timestamp).Replace("-", "");
                                        ntlmChallenge = httpSessionTable[sessionTimestamp].ToString();
                                    }
                                    catch
                                    {
                                        ntlmChallenge = "";
                                    }

                                }

                                OutputNTLM(type, listenerPort, sourceIP, sourcePort, user, domain, host, ntlmChallenge, ntlmResponseHash, lmResponseHash);

                                if (type.Equals("Proxy"))
                                {

                                    if (!string.IsNullOrEmpty(HTTPResponse))
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
                            OutputCleartext(type, listenerPort, sourceIP, sourcePort, cleartextCredentials);
                        }

                        if (!string.IsNullOrEmpty(WPADResponse) && !proxyIgnoreMatch && string.Equals(request.URI, "/wpad.dat"))
                        {
                            response.ContentType = "application/x-ns-proxy-autoconfig";
                            response.Message = Encoding.UTF8.GetBytes(WPADResponse);
                        }
                        else if (!string.IsNullOrEmpty(HTTPResponse))
                        {
                            response.Message = Encoding.UTF8.GetBytes(HTTPResponse);
                        }

                        if (EnabledWebDAV)
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

                                if (ntlmStage == 3 || (!string.IsNullOrEmpty(request.Authorization) && request.Authorization.ToUpper().StartsWith("BASIC ")) || HTTPAuth.Equals("ANONYMOUS"))
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

                                if (!tcpSessionTable.ContainsKey(sourceIP) || DateTime.Compare((DateTime)tcpSessionTable[sourceIP], DateTime.Now) <= 0)
                                {
                                    tcpSessionTable[sourceIP] = DateTime.Now.AddSeconds(1);
                                }

                            }
                            else
                            {
                                tcpClient.Close();
                            }

                        }

                    }

                }

            }
            catch (Exception ex)
            {
                OutputError(ex, type, port);
            }

        }

        protected virtual void OutputUserAgent(string protocol, string listenerPort, string clientIP, string clientPort, string userAgent)
        {

        }

        protected virtual void OutputChallenge(string protocol, string listenerPort, string clientIP, string clientPort, string challenge)
        {

        }

        protected virtual void OutputHostHeader(string protocol, string listenerPort, string clientIP, string clientPort, string hostHeader)
        {

        }

        protected virtual void OutputRequestMethod(string protocol, string listenerPort, string clientIP, string clientPort, string uri, string method)
        {

        }

        protected virtual void OutputCleartext(string protocol, string listenerPort, string clientIP, string clientPort, string credentials)
        {

        }

        protected virtual void OutputNTLM(string protocol, string listenerPort, string clientIP, string clientPort, string user, string domain, string host, string ntlmChallenge, string ntlmResponseHash, string lmResponseHash)
        {

        }

        protected virtual void OutputIgnore(string protocol, string listenerPort, string clientIP, string clientPort, string message)
        {

        }
        protected virtual void OutputError(Exception ex, string protocol, int port)
        {

        }

    }
}
