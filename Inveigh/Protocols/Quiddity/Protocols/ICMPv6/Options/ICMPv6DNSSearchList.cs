using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.ICMPv6
{
    class ICMPv6DNSSearchList
    {
        // https://datatracker.ietf.org/doc/html/rfc8106
        public byte Type { get; set; }
        public byte Length { get; set; }
        public ushort Reserved { get; set; }
        public uint Lifetime { get; set; }
        public byte[] DomainNames { get; set; }

        public ICMPv6DNSSearchList()
        {
            this.Type = 31;
            this.Length = 0;
            this.Reserved = 0;
            this.Lifetime = 0;
        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.Type);
                packetWriter.Write(this.Length);
                packetWriter.Write(this.Reserved);
                packetWriter.BigEndianWrite(this.Lifetime);
                packetWriter.Write(this.DomainNames);
                return memoryStream.ToArray();
            }

        }

    }
}
