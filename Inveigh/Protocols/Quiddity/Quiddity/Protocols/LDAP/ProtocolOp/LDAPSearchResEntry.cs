using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;

namespace Quiddity.LDAP
{
    class LDAPSearchResEntry
    {
        public string ObjectDN { get; set; }
        public byte[] Attributes { get; set; }

        public byte[] Encode()
        {
            return BerConverter.Encode("t{stX}", new object[] { 0x64, this.ObjectDN, 0x30, this.Attributes } );
        }

        public byte[] Encode(Object[] Segment)
        {
            return BerConverter.Encode("t{s{V}}", 0x64, this.ObjectDN, Segment);
        }

    }
}
