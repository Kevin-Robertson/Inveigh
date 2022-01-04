using Quiddity.Support;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.DNS
{
    class DNSRecordSRV : DNSResource
    {
        // https://datatracker.ietf.org/doc/html/rfc2782
        public byte[] Service { get; set; }
        public byte[] Proto { get; set; }
        public ushort Priority { get; set; }
        public ushort Weight { get; set; }
        public ushort Port { get; set; }
        public byte[] Target { get; set; }

        public DNSRecordSRV()
        {
            this.Priority = 0;
            this.Weight = 100;
        }

        public byte[] GetBytes(string target, ushort port)
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.BigEndianWrite(this.Priority);
                packetWriter.BigEndianWrite(this.Weight);
                packetWriter.BigEndianWrite(port);
                packetWriter.Write(Utilities.GetDNSNameBytes(target, true));
                return memoryStream.ToArray();
            }

        }

    }
}
