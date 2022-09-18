/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2022, Kevin Robertson
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
using Quiddity.LDAP;
using Quiddity.NTLM;
using Quiddity.Support;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Quiddity
{
    class LDAPListener
    {

        public string Challenge { get; set; }
        public string NetbiosDomain { get; set; }
        public string ComputerName { get; set; }
        public string DNSDomain { get; set; }

        public static bool isRunning = false;

        internal void Start(IPAddress ipAddress, int port)
        {
            TCPListener tcpListener = new TCPListener(ipAddress, port);
            IAsyncResult tcpAsync;

            try
            {
                tcpListener.Start();
                isRunning = true;

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
                                object[] parameters = { tcpClient, port };
                                ThreadPool.QueueUserWorkItem(new WaitCallback(ReceiveClient), parameters);
                            }

                        }
                        catch (Exception ex)
                        {
                            OutputError(ex, port);
                        }

                    }

                }

            }
            catch (Exception ex)
            {
                OutputError(ex, port);
            }

        }

        internal void ReceiveClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            TcpClient tcpClient = (TcpClient)parameterArray[0];
            int port = (int)parameterArray[1];
            NetworkStream tcpStream = tcpClient.GetStream();
            string ntlmChallenge = "";
            string clientIP = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Address.ToString();
            string clientPort = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Port.ToString();
            string listenerPort = ((IPEndPoint)(tcpClient.Client.LocalEndPoint)).Port.ToString();

            try
            {

                while (tcpClient.Connected && isRunning)
                {
                    byte[] requestData = new byte[4096];

                    do
                    {
                        Thread.Sleep(100);
                    }
                    while (!tcpStream.DataAvailable && tcpClient.Connected);

                    while (tcpStream.DataAvailable)
                    {
                        tcpStream.Read(requestData, 0, requestData.Length);
                    }

                    LDAPMessage message = new LDAPMessage();
                    message.Decode(requestData);
                    LDAPMessage message2 = new LDAPMessage();
                    message2.MessageID = message.MessageID;
                    byte[] buffer = new byte[0];
                    OutputConnection(listenerPort, clientIP, clientPort, message.Tag);

                    if (message.Tag == 3)
                    {
                        LDAPMessage message3 = new LDAPMessage();
                        message3.MessageID = message.MessageID;
                        LDAPSearchRequest searchRequest = new LDAPSearchRequest();
                        searchRequest.ReadBytes((byte[][])message.ProtocolOp);

                        LDAPSearchResDone resdone = new LDAPSearchResDone();
                        resdone.ResultCode = 0;
                        LDAPSearchResEntry search = new LDAPSearchResEntry();

                        if (String.Equals(searchRequest.Attributes[0], "supportedCapabilities"))
                        {
                            LDAPSupportedCapabilities cap = new LDAPSupportedCapabilities();
                            search.Attributes = cap.Encode();
                        }
                        else if (String.Equals(searchRequest.Attributes[0], "supportedSASLMechanisms"))
                        {
                            LDAPSupportedSASLMechanisms mech = new LDAPSupportedSASLMechanisms();
                            search.Attributes = mech.Encode();
                        }

                        message2.ProtocolOp = search;
                        message3.ProtocolOp = resdone;
                        buffer = Utilities.BlockCopy(message2.Encode(4), message3.Encode(5));
                    }
                    else if (message.Tag == 0)
                    {
                        LDAPBindRequest bind = new LDAPBindRequest();
                        bind.ReadBytes((byte[][])message.ProtocolOp);
                        LDAPSaslCredentials sasl = new LDAPSaslCredentials();
                        sasl.ReadBytes(bind.Authentication);
                        NTLMNegotiate ntlm = new NTLMNegotiate();
                        ntlm.ReadBytes(sasl.Credentials, 0);

                        if (ntlm.MessageType == 1)
                        {
                            NTLMChallenge challenge = new NTLMChallenge(Challenge, NetbiosDomain, ComputerName, DNSDomain, ComputerName, DNSDomain);
                            byte[] challengeData = challenge.GetBytes(ComputerName);
                            ntlmChallenge = BitConverter.ToString(challenge.ServerChallenge).Replace("-", "");

                            LDAPBindResponse bindResponse = new LDAPBindResponse
                            {
                                ServerSaslCreds = challengeData
                            };

                            LDAPMessage bindMessage = new LDAPMessage
                            {
                                MessageID = message.MessageID,
                                ProtocolOp = bindResponse
                            };

                            buffer = bindMessage.Encode(3);
                            OutputChallenge(listenerPort, clientIP, clientPort, ntlmChallenge);
                        }
                        else if (ntlm.MessageType == 3)
                        {
                            NTLMResponse ntlmResponse = new NTLMResponse(sasl.Credentials, false);
                            string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                            string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                            string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                            string response2 = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-", "");
                            string lmResponse = BitConverter.ToString(ntlmResponse.LmChallengeResponse).Replace("-", "");
                            OutputNTLM("LDAP", listenerPort, clientIP, clientPort, user, domain, host, ntlmChallenge, response2, lmResponse);
                        }

                    }

                    tcpStream.Write(buffer, 0, buffer.Length);
                    tcpStream.Flush();
                }

            }
            catch (Exception ex)
            {
                OutputError(ex, port);
            }

        }

        protected virtual void OutputConnection(string listenerPort, string clientIP, string clientPort, int tag)
        {

        }

        protected virtual void OutputNTLM(string protocol, string listenerPort, string clientIP, string clientPort, string user, string domain, string host, string ntlmChallenge, string ntlmResponseHash, string lmResponseHash)
        {

        }

        protected virtual void OutputChallenge(string listenerPort, string clientIP, string clientPort, string challenge)
        {

        }

        protected virtual void OutputError(Exception ex, int port)
        {

        }

    }
}
