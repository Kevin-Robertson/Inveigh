using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.DHCPv6
{
    class DHCPv6Option
    {
        public ushort OptionCode { get; set; }
        public ushort OptionLen { get; set; }

        public DHCPv6Option()
        {

        }

        public DHCPv6Option(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public void ReadBytes(byte[] data, int index)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = index;
                this.OptionCode = packetReader.BigEndianReadUInt16();
                this.OptionLen = packetReader.BigEndianReadUInt16();
            }

        }

    }
    
}
