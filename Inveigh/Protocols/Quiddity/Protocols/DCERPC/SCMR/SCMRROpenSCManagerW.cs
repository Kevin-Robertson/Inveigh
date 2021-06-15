using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Quiddity.SCMR
{
    public class SCMRROpenSCManagerW
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2
        public byte[] LpMachineName { get; set; }
        public byte[] LpDatabaseName { get; set; }
        public byte[] DwDesiredAccess { get; set; }
    }
}
