using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Quiddity.SMB2
{
    enum OplockLevel : uint
    {
        SMB2_OPLOCK_LEVEL_NONE = 0x00,
        SMB2_OPLOCK_LEVEL_II = 0x01,
        SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x08,
        SMB2_OPLOCK_LEVEL_BATCH = 0x09,
        SMB2_OPLOCK_LEVEL_LEASE = 0xFF
    }

    enum CreateAction : uint
    {
        FILE_SUPERSEDED = 0x00000000,
        FILE_OPENED = 0x00000001,
        FILE_CREATED = 0x00000002,
        FILE_OVERWRITTEN = 0x00000003
    }

    class SMB2CreateResponse
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927
        public ushort StructureSize { get; set; }
        public byte OplockLevel { get; set; }
        public byte Flags { get; set; }
        public uint CreateAction { get; set; }
        public byte[] CreationTime { get; set; }
        public byte[] LastAccessTime { get; set; }
        public byte[] LastWriteTime { get; set; }
        public byte[] ChangeTime { get; set; }
        public byte[] AllocationSize { get; set; }
        public byte[] EndofFile { get; set; }
        public byte[] FileAttributes { get; set; }
        public byte[] Reserved2 { get; set; }
        public byte[] Field { get; set; }
        public uint CreateContextsOffset { get; set; }
        public uint CreateContextsLength { get; set; }
        public byte[] Buffer { get; set; }
    }
}
