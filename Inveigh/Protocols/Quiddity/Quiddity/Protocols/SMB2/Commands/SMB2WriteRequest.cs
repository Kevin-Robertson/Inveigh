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
    enum Channel : uint
    {
        SMB2_CHANNEL_NONE = 0x00000001,
        SMB2_CHANNEL_RDMA_V1 = 0x0000002,
        SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x00000003,
        SMB2_CHANNEL_RDMA_TRANSFORM = 0x0000004
    }

    enum WriteRequestFlags : uint // Flags
    {
        SMB2_WRITEFLAG_WRITE_THROUGH = 0x00000001,
        SMB2_WRITEFLAG_WRITE_UNBUFFERED = 0x0000002
    }

    class SMB2WriteRequest
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8
        public ushort StructureSize { get; set; }
        public ushort DataOffset { get; set; }
        public uint Length { get; set; }
        public ulong Offset { get; set; }
        public byte[] Field { get; set; }
        public uint Channel { get; set; }
        public uint RemainingBytes { get; set; }
        public ushort WriteChannelInfoOffset { get; set; }
        public ushort WriteChannelInfoLength { get; set; }
        public uint Flags { get; set; }
        public byte[] Buffer { get; set; }
    }
}
