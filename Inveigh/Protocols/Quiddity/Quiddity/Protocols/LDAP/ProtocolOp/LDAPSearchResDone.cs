using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.Protocols;

namespace Quiddity.LDAP
{
    class LDAPSearchResDone
    {
        public int ResultCode { get; set; }
        public byte[] MatchedDN { get; set; }
        public byte[] ErrorMessage { get; set; }

        public byte[] Encode()
        {
            return BerConverter.Encode("t{eoo}", 0x65, this.ResultCode, this.MatchedDN, this.ErrorMessage); ;
        }

    }

}
