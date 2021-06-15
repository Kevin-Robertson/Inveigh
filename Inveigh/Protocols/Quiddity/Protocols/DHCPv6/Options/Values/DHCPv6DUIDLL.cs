using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.DHCPv6
{
    public class DHCPv6DUIDLL
    {
        // https://datatracker.ietf.org/doc/html/rfc3315#section-9
        public ushort DUIDType { get; set; }
        public ushort HardwareType { get; set; }
        public byte[] LinkLayerAddress { get; set; }

        public DHCPv6DUIDLL()
        {

        }

        public DHCPv6DUIDLL(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public DHCPv6DUIDLL(string linkLayerAddress)
        {
            byte[] linkLayerAddressData = new byte[6];
            int i = 0;

            foreach (string character in linkLayerAddress.Split(':'))
            {
                linkLayerAddressData[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                i++;
            }

            this.DUIDType = 3;
            this.HardwareType = 1;
            this.LinkLayerAddress = linkLayerAddressData;
        }

        public void ReadBytes(byte[] data, int index)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = index;
                this.DUIDType = packetReader.BigEndianReadUInt16();
                this.HardwareType = packetReader.BigEndianReadUInt16();
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
