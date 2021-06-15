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
using Quiddity.SMB2;

namespace Quiddity.SMB2
{
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
    enum RequestedOplockLevel : byte
    {
        SMB2_OPLOCK_LEVEL_NONE = 0x00,
        SMB2_OPLOCK_LEVEL_II = 0x01,
        SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x08,
        SMB2_OPLOCK_LEVEL_BATCH = 0x09,
        SMB2_OPLOCK_LEVEL_LEASE = 0xFF
    }

    enum ImpersonationLevel : uint
    {
        Anonymous = 0x00000000,
        Identification = 0x00000001,
        Impersonation = 0x00000002,
        Delegate = 0x00000003
    }

    enum ShareAccess : uint
    {
        FILE_SHARE_READ = 0x00000000,
        FILE_SHARE_WRITE = 0x0000002,
        FILE_SHARE_DELETE = 0x00000004
    }

    enum CreateDisposition : uint
    {
        FILE_SUPERSEDE = 0x00000000,
        FILE_OPEN = 0x0000001,
        FILE_CREATE = 0x00000002,
        FILE_OPEN_IF = 0x00000003,
        FILE_OVERWRITE = 0x00000004,
        FILE_OVERWRITE_IF = 0x00000005
    }

    enum CreateOptions : uint
    {
        FILE_DIRECTORY_FILE = 0x00000000,
        FILE_WRITE_THROUGH = 0x0000001,
        FILE_SEQUENTIAL_ONLY = 0x00000004,
        FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,
        FILE_SYNCHRONOUS_IO_ALERT = 0x00000010,
        FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020,
        FILE_NON_DIRECTORY_FILE = 0x00000040,
        FILE_COMPLETE_IF_OPLOCKED = 0x00000100,
        FILE_NO_EA_KNOWLEDGE = 0x00000200,
        FILE_RANDOM_ACCESS = 0x00000800,
        FILE_DELETE_ON_CLOSE = 0x00001000,
        FILE_OPEN_BY_FILE_ID = 0x00002000,
        FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000,
        FILE_NO_COMPRESSION = 0x00008000,
        FILE_OPEN_REMOTE_INSTANCE = 0x00000400,
        FILE_OPEN_REQUIRING_OPLOCK = 0x00010000,
        FILE_DISALLOW_EXCLUSIVE = 0x00020000,
        FILE_RESERVE_OPFILTER = 0x00100000,
        FILE_OPEN_REPARSE_POINT = 0x00200000,
        FILE_OPEN_NO_RECALL = 0x00400000,
        FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
    }

    class SMB2CreateRequest
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
        public ushort StructureSize { get; set; }
        public byte Flags { get; set; }
        public byte RequestedOplockLevel { get; set; }
        public uint ImpersonationLevel { get; set; }
        public byte[] SmbCreateFlags { get; set; }
        public byte[] Reserved { get; set; }
        public byte[] DesiredAccess { get; set; }
        public byte[] FileAttributes { get; set; }
        public uint ShareAccess { get; set; }
        public uint CreateDisposition { get; set; }
        public uint CreateOptions { get; set; }
        public ushort NameOffset { get; set; }
        public ushort NameLength { get; set; }
        public uint CreateContextsOffset { get; set; }
        public uint CreateContextsLength { get; set; }
        public byte[] Buffer { get; set; }
    }
}
