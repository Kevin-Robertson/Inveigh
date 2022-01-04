using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Quiddity.LDAP
{
    class LDAPPartialAttributeList
    {
        public string Type { get; set; }
        public string[] Vals { get; set; }
    }
}
