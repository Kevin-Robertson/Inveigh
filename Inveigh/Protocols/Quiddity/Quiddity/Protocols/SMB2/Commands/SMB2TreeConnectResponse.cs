/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Kevin Robertson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Quiddity.SMB2
{

    enum ShareType : byte
    {
        SMB2_SHARE_TYPE_DISK = 0x01,
        SMB2_SHARE_TYPE_PIPE = 0x02,
        SMB2_SHARE_TYPE_PRINT = 0x03
    }

    enum ShareFlags : uint
    {
        SMB2_SHAREFLAG_MANUAL_CACHING = 0x00000000,
        SMB2_SHAREFLAG_AUTO_CACHING = 0x00000010,
        SMB2_SHAREFLAG_VDO_CACHING = 0x00000020,
        SMB2_SHAREFLAG_NO_CACHING = 0x00000030,
        SMB2_SHAREFLAG_DFS = 0x00000001,
        SMB2_SHAREFLAG_DFS_ROOT = 0x00000002,
        SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100,
        SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200,
        SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400,
        SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800,
        SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000,
        SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x00002000,
        SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x00004000,
        SMB2_SHAREFLAG_ENCRYPT_DATA = 0x00008000,
        SMB2_SHAREFLAG_IDENTITY_REMOTING = 0x00040000,
        SMB2_SHAREFLAG_COMPRESS_DATA = 0x00100000
    }

    enum Capabilities : uint
    {
        SMB2_SHARE_CAP_DFS = 0x00000008,
        SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010,
        SMB2_SHARE_CAP_SCALEOUT = 0x00000020,
        SMB2_SHARE_CAP_CLUSTER = 0x00000040,
        SMB2_SHARE_CAP_ASYMMETRIC = 0x00000080,
        SMB2_SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100
    }


    class SMB2TreeConnectResponse
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96
        public ushort StructureSize { get; set; }
        public byte ShareType { get; set; }
        public byte Reserved { get; set; }
        public uint ShareFlags { get; set; }
        public uint Capabilities { get; set; }
        public uint MaximalAccess { get; set; }
    }
}
