using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace Quiddity.DNS
{
    class DNSRecordA
    {
        public byte[] Address { get; set; }

        public DNSRecordA()
        {

        }

        public DNSRecordA(string address)
        {
            this.Address = IPAddress.Parse(address).GetAddressBytes();
        }
        public byte[] GetBytes()
        {
            return this.Address;
        }

        public byte[] GetBytes(string address)
        {
            return IPAddress.Parse(address).GetAddressBytes();
        }

    }
}
