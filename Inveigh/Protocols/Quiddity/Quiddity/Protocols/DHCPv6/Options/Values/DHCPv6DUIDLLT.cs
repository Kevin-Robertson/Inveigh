using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.DHCPv6
{
    public class DHCPv6DUIDLLT
    {
        // https://datatracker.ietf.org/doc/html/rfc3315#section-9
        public ushort DUIDType { get; set; }
        public ushort HardwareType { get; set; }
        public uint Time { get; set; }
        public byte[] LinkLayerAddress { get; set; }

        public DHCPv6DUIDLLT()
        {

        }

        public DHCPv6DUIDLLT(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public void ReadBytes(byte[] data, int index)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = index;
                this.DUIDType = packetReader.BigEndianReadUInt16();
                this.HardwareType = packetReader.BigEndianReadUInt16();
                this.Time = packetReader.BigEndianReadUInt32();
                this.LinkLayerAddress = packetReader.ReadBytes(6);
            }

        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.BigEndianWrite(this.DUIDType);
                packetWriter.BigEndianWrite(this.HardwareType);
                packetWriter.Write(this.LinkLayerAddress);
                return memoryStream.ToArray();
            }

        }

    }
}
