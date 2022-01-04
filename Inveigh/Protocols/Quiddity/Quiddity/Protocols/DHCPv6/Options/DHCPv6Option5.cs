using Quiddity.Support;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace Quiddity.DHCPv6
{
    class DHCPv6Option5 : DHCPv6Option
    {
        // https://datatracker.ietf.org/doc/html/rfc3315#section-22.6

        public byte[] IPv6Address { get; set; }
        public uint PreferredLifetime { get; set; }
        public uint ValidLifetime { get; set; }
        public byte[] IAAddrOptions { get; set; }

        public DHCPv6Option5()
        {
        }

        public DHCPv6Option5(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public DHCPv6Option5(byte[] data, int index)
        {
            ReadBytes(data, index);
        }

        public new void ReadBytes(byte[] data, int index)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = index;
                this.OptionCode = packetReader.BigEndianReadUInt16();
                this.OptionLen = packetReader.BigEndianReadUInt16();
                this.IPv6Address = packetReader.ReadBytes(16);
                this.PreferredLifetime = packetReader.BigEndianReadUInt32();
                this.ValidLifetime = packetReader.BigEndianReadUInt32();
            }

        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.BigEndianWrite(this.OptionCode);
                packetWriter.BigEndianWrite(this.OptionLen);
                packetWriter.Write(this.IPv6Address);
                packetWriter.BigEndianWrite(this.PreferredLifetime);
                packetWriter.BigEndianWrite(this.ValidLifetime);
                return memoryStream.ToArray();
            }

        }

        public byte[] GetBytes(string ipv6Address, uint lifeTime)
        {
            this.OptionCode = 5;
            this.OptionLen = 24;
            this.IPv6Address = IPAddress.Parse(ipv6Address).GetAddressBytes();
            this.PreferredLifetime = lifeTime;
            this.ValidLifetime = lifeTime;
            return GetBytes();
        }

    }
}
