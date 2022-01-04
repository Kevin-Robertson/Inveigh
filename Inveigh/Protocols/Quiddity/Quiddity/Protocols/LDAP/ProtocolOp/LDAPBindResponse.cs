using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Quiddity.LDAP
{
    class LDAPBindResponse : LDAPResult
    {
        public byte[] ServerSaslCreds { get; set; }

        public LDAPBindResponse()
        {
            this.ResultCode = 14;
        }

    }
}
