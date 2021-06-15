using Quiddity.Support;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.DNS
{
    class DNSRecordSOA
    {
        // https://tools.ietf.org/html/rfc1035
        public byte[] MName { get; set; }
        public byte[] RName { get; set; }
        public uint Serial { get; set; }
        public uint Refresh { get; set; }
        public uint Retry { get; set; }
        public uint Expire { get; set; }
        public uint Minium { get; set; }

        public DNSRecordSOA()
        {
            this.Refresh = 900;
            this.Retry = 600;
            this.Expire = 86400;
            this.Minium = 3600;
        }

        public DNSRecordSOA(uint serial)
        {
            this.Serial = serial;
            this.Refresh = 900;
            this.Retry = 600;
            this.Expire = 86400;
            this.Minium = 3600;
        }

        public byte[] GetBytes()
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.MName);
                packetWriter.Write(this.RName);
                packetWriter.BigEndianWrite(this.Serial);
                packetWriter.BigEndianWrite(this.Refresh);
                packetWriter.BigEndianWrite(this.Retry);
                packetWriter.BigEndianWrite(this.Expire);
                packetWriter.BigEndianWrite(this.Minium);
                return memoryStream.ToArray();
            }
        }

        public byte[] GetBytes(string host, ushort index)
        {
            index |= (1 << 15);
            index |= (1 << 14);
            byte[] indexData = BitConverter.GetBytes(index);
            Array.Reverse(indexData);

            byte[] hostData = Utilities.GetDNSNameBytes(host, false);
            byte[] hostCompressed = new byte[hostData[0] + 3];
            Buffer.BlockCopy(hostData, 0, hostCompressed, 0, hostData[0] + 1);
            Buffer.BlockCopy(indexData, 0, hostCompressed, hostCompressed.Length - 2, 2);
            byte[] authoritytData = Utilities.GetDNSNameBytes("hostmaster", false);
            byte[] authorityCompressed = new byte[authoritytData[0] + 3];
            Buffer.BlockCopy(authoritytData, 0, authorityCompressed, 0, authoritytData[0] + 1);
            Buffer.BlockCopy(indexData, 0, authorityCompressed, authorityCompressed.Length - 2, 2);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(hostCompressed);
                packetWriter.Write(authorityCompressed);
                packetWriter.BigEndianWrite(this.Serial);
                packetWriter.BigEndianWrite(this.Refresh);
                packetWriter.BigEndianWrite(this.Retry);
                packetWriter.BigEndianWrite(this.Expire);
                packetWriter.BigEndianWrite(this.Minium);
                return memoryStream.ToArray();
            }
        }

    }
}
