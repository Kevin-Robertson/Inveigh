using Quiddity.Support;
using Quiddity.UDP;
using System;
using System.Net;
using System.Net.Sockets;

namespace Inveigh
{
    class UDPSocket
    {
        public static void SendTo(string clientIP, int clientPort, string sourceIP, int sourcePort, byte[] buffer, bool isIPv6)
        {
            IPAddress clientIPAddress = IPAddress.Parse(clientIP);
            AddressFamily addressFamily = AddressFamily.InterNetwork;
            SocketOptionLevel socketOptionLevel = SocketOptionLevel.IP;
            IPAddress sourceIPAddress = IPAddress.Parse(sourceIP);
            int networkInterfaceIndex = Program.networkInterfaceIndexIPv4;

            UDPHeader header = new UDPHeader
            {
                SourcePort = (ushort)sourcePort,
                DestinationPort = (ushort)clientPort,
                Length = (ushort)(buffer.Length + 8)
            };

            if (String.Equals(clientIPAddress.AddressFamily.ToString(), "InterNetworkV6"))
            {
                sourceIPAddress = IPAddress.Parse(sourceIP);
                networkInterfaceIndex = Program.networkInterfaceIndexIPv6;
                addressFamily = AddressFamily.InterNetworkV6;
                socketOptionLevel = SocketOptionLevel.IPv6;
                byte[] checksumBuffer = Utilities.BlockCopy(header.GetBytes(), buffer);
                header.IPv6Checksum(checksumBuffer, clientIP, sourceIPAddress.ToString(), 17);
            }

            buffer = Utilities.BlockCopy(header.GetBytes(), buffer);

            Socket socket = new Socket(addressFamily, SocketType.Raw, ProtocolType.Udp)
            {
                SendBufferSize = 1024
            };

            socket.SetSocketOption(socketOptionLevel, SocketOptionName.MulticastInterface, networkInterfaceIndex);
            IPEndPoint ipEndPoint = new IPEndPoint(sourceIPAddress, sourcePort);
            socket.Bind(ipEndPoint);
            IPEndPoint clientEndpoint = new IPEndPoint(clientIPAddress, clientPort);
            socket.SendTo(buffer, clientEndpoint);
            socket.Close();
        }

    }

}
