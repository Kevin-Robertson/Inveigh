using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Quiddity.LDAP
{
    class LDAPBindRequest
    {
        public byte[] Version { get; set; }
        public byte[] Name { get; set; }
        public byte[] Authentication { get; set; }

        public void ReadBytes(byte[][] Data)
        {
            this.Version = (byte[])Data.GetValue(0);
            this.Name = (byte[])Data.GetValue(1);
            this.Authentication = (byte[])Data.GetValue(2);
        }

    }

}
