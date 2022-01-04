using Quiddity.Support;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.LDAP
{
    class LDAPSearchRequest
    {
        public byte[] BaseObject { get; set; }
        public byte[] Scope { get; set; }
        public byte[] DerefAliases { get; set; }
        public byte[] SizeLimit { get; set; }
        public byte[] TimeLimit { get; set; }
        public byte[] TypesOnly { get; set; }
        public byte[] Filter { get; set; }
        public string[] Attributes { get; set; }

        public void ReadBytes(byte[][] Data)
        {
            this.BaseObject = (byte[])Data.GetValue(0);
            this.Scope = (byte[])Data.GetValue(1);
            this.DerefAliases = (byte[])Data.GetValue(2);
            this.SizeLimit = (byte[])Data.GetValue(3);
            this.TimeLimit = (byte[])Data.GetValue(4);
            this.TypesOnly = (byte[])Data.GetValue(5);
            this.Filter = (byte[])Data.GetValue(6);
            this.Attributes = ASN1.DecodeOctetStringArray((byte[])Data.GetValue(7));
        }

        public object[] Decode(byte[] Data)
        {
            return BerConverter.Decode("{OiiiiiOO}", Data);
        }

        public object[] Decode2(byte[] Data)
        {
            return BerConverter.Decode("{B}", Data);
        }

    }

}
