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
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Quiddity.NetBIOS;
using Quiddity.NTLM;
using Quiddity.SMB;
using Quiddity.SMB2;
using Quiddity.Support;

namespace Quiddity
{
    class SMBListener
    {
        public string Challenge { get; set; }
        public string NetbiosDomain { get; set; }
        public string ComputerName { get; set; }
        public string DNSDomain { get; set; }

        public static bool isRunning = false;
        public static ulong smb2Session = 5548434740922023936;

        internal void Start(IPAddress ipAddress, int port)
        {
            TCPListener tcpListener = new TCPListener(ipAddress, port);
            IAsyncResult tcpAsync;
            TcpClient tcpClient;
            Guid guid = Guid.NewGuid();

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
                                tcpClient = tcpListener.EndAcceptTcpClient(tcpAsync);
                                object[] parameters = { guid, tcpClient, port };
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
            Guid serverGuid = (Guid)parameterArray[0];     
            TcpClient tcpClient = (TcpClient)parameterArray[1];
            int port = (int)parameterArray[2];
            NetworkStream tcpStream = tcpClient.GetStream();
            bool isSMB2;
            string challenge = "";
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

                    NetBIOSSessionService requestNetBIOSSessionService = new NetBIOSSessionService(requestData);
                    SMBHelper smbHelper = new SMBHelper(); // todo check

                    if (requestNetBIOSSessionService.Type == 0 || smbHelper.Protocol[0] == 0xfe || smbHelper.Protocol[0] == 0xff)
                    {
                        int sessionServiceIndex = 0;

                        if (requestNetBIOSSessionService.Type == 0)
                        {
                            sessionServiceIndex = 4;
                        }

                        byte[] sendBuffer = new byte[0];
                        SMBHeader requestSMBHeader = new SMBHeader();
                        SMB2Header requestSMB2Header = new SMB2Header();
                        smbHelper.ReadBytes(requestData, sessionServiceIndex);

                        if (smbHelper.Protocol[0] == 0xfe)
                        {
                            isSMB2 = true;
                            requestSMB2Header.ReadBytes(requestData, sessionServiceIndex);
                        }
                        else
                        {
                            isSMB2 = false;
                            requestSMBHeader.ReadBytes(requestData, sessionServiceIndex);
                        }

                        if (!isSMB2 && requestSMBHeader.Command == 0x72 || (isSMB2 && requestSMB2Header.Command == 0))
                        {
                            SMB2NegotiatelRequest smb2NegotiatelRequest = new SMB2NegotiatelRequest(requestData, 64 + sessionServiceIndex);
                            SMB2Header responseSMB2Header = new SMB2Header();
                            SMB2NegotiateResponse smb2NegotiateResponse = new SMB2NegotiateResponse();

                            if (!isSMB2)
                            {
                                smb2NegotiateResponse.DialectRivision = new byte[2] { 0xff, 0x02 };
                                smb2NegotiateResponse.Capabilities = new byte[4] { 0x07, 0x00, 0x00, 0x00 };
                                OutputNegotiation("SMB1", listenerPort, clientIP, clientPort);
                            }
                            else if (isSMB2)
                            {
                                responseSMB2Header.MessageId = requestSMB2Header.MessageId;

                                if (smb2NegotiatelRequest.GetMaxDialect() == 0x311)
                                {
                                    smb2NegotiateResponse.DialectRivision = new byte[2] { 0x11, 0x03 };
                                    smb2NegotiateResponse.NegotiateContextCount = 3;
                                    smb2NegotiateResponse.Capabilities = new byte[4] { 0x2f, 0x00, 0x00, 0x00 };
                                    smb2NegotiateResponse.NegotiateContextOffset = 448;
                                    smb2NegotiateResponse.NegotiateContextList = new SMB2NegotiateContext().GetBytes(new string[] { "1", "2", "3" });
                                    OutputNegotiation("SMB3", listenerPort, clientIP, clientPort);
                                }
                                else
                                {
                                    smb2NegotiateResponse.DialectRivision = new byte[2] { 0x10, 0x02 };
                                    smb2NegotiateResponse.Capabilities = new byte[4] { 0x07, 0x00, 0x00, 0x00 };
                                    OutputNegotiation("SMB2", listenerPort, clientIP, clientPort);
                                }

                                responseSMB2Header.Reserved2 = requestSMB2Header.Reserved2; // todo fix
                            }

                            smb2NegotiateResponse.EncodeBuffer();
                            smb2NegotiateResponse.ServerGUID = serverGuid.ToByteArray();
                            sendBuffer = SMB2Helper.GetBytes(new NetBIOSSessionService(), responseSMB2Header, smb2NegotiateResponse);
                        }
                        else if (isSMB2 && requestSMB2Header.Command > 0)
                        {

                            switch (requestSMB2Header.Command)
                            {

                                case 1:
                                    {
                                        SMB2SessionSetupRequest smb2SessionSetupRequest = new SMB2SessionSetupRequest(requestData, 64 + sessionServiceIndex);
                                        NTLMNegotiate requestNTLMNegotiate = new NTLMNegotiate(smb2SessionSetupRequest.Buffer, true);

                                        if (requestNTLMNegotiate.MessageType == 1)
                                        {
                                            SMB2Header responseSMB2Header = new SMB2Header();
                                            SMB2SessionSetupResponse smb2SessionSetupResponse = new SMB2SessionSetupResponse();
                                            responseSMB2Header.Status = new byte[4] { 0x16, 0x00, 0x00, 0xc0 };
                                            responseSMB2Header.CreditCharge = 1;
                                            responseSMB2Header.Reserved2 = requestSMB2Header.Reserved2;
                                            responseSMB2Header.Command = 1;
                                            responseSMB2Header.Flags = new byte[4] { 0x11, 0x00, 0x00, 0x00 };
                                            responseSMB2Header.MessageId = requestSMB2Header.MessageId;
                                            responseSMB2Header.SessionId = BitConverter.GetBytes(smb2Session);
                                            smb2Session++;
                                            smb2SessionSetupResponse.Pack(Challenge, NetbiosDomain, ComputerName, DNSDomain, ComputerName, DNSDomain, out byte[] challengeData);
                                            sendBuffer = SMB2Helper.GetBytes(new NetBIOSSessionService(), responseSMB2Header, smb2SessionSetupResponse);
                                            challenge = BitConverter.ToString(challengeData).Replace("-", "");
                                            OutputChallenge(listenerPort, clientIP, clientPort, challenge);
                                        }
                                        else if (requestNTLMNegotiate.MessageType == 3)
                                        {
                                            NTLMResponse ntlmResponse = new NTLMResponse(smb2SessionSetupRequest.Buffer, true);
                                            string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                                            string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                                            string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                                            string response = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-", "");
                                            string lmResponse = "";

                                            if (!Utilities.ArrayIsNullOrEmpty(ntlmResponse.UserName))
                                            {
                                                lmResponse = BitConverter.ToString(ntlmResponse.LmChallengeResponse).Replace("-", "");
                                            }

                                            OutputNTLM("SMB", listenerPort, clientIP, clientPort, user, domain, host, challenge, response, lmResponse);
                                            SMB2Header responseSMB2Header = new SMB2Header();
                                            SMB2SessionSetupResponse smb2SessionSetupResponse = new SMB2SessionSetupResponse();
                                            responseSMB2Header.Status = new byte[4] { 0x6d, 0x00, 0x00, 0xc0 };
                                            //responseSMB2Header.Status = new byte[4] { 0x00, 0x00, 0x00, 0x00 };
                                            //responseSMB2Header.Status = new byte[4] { 0x22, 0x00, 0x00, 0xc0 }; //access denied
                                            responseSMB2Header.CreditCharge = 1;
                                            responseSMB2Header.Reserved2 = requestSMB2Header.Reserved2;
                                            responseSMB2Header.Command = 1;
                                            responseSMB2Header.Flags = new byte[4] { 0x11, 0x00, 0x00, 0x00 };
                                            responseSMB2Header.MessageId = requestSMB2Header.MessageId;
                                            responseSMB2Header.SessionId = requestSMB2Header.SessionId;
                                            smb2SessionSetupResponse.SecurityBufferOffset = 0;
                                            sendBuffer = SMB2Helper.GetBytes(new NetBIOSSessionService(), responseSMB2Header, smb2SessionSetupResponse);
                                        }

                                    }
                                    break;

                            }

                        }

                        tcpStream.Write(sendBuffer, 0, sendBuffer.Length);
                        tcpStream.Flush();
                    }
                    else
                    {
                        tcpClient.Close();
                    }

                }

            }
            catch (Exception ex)
            {
                OutputError(ex, port);
            }

        }

        protected virtual void OutputNTLM(string protocol, string listenerPort, string clientIP, string clientPort, string user, string domain, string host, string ntlmChallenge, string ntlmResponseHash, string lmResponseHash)
        {

        }

        protected virtual void OutputChallenge(string listenerPort, string clientIP, string clientPort, string challenge)
        {

        }

        protected virtual void OutputNegotiation(string protocol, string listenerPort, string clientIP, string clientPort)
        {

        }

        protected virtual void OutputError(Exception ex, int port)
        {

        }

    }

}
