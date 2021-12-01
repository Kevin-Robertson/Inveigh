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
using System.IO;
using System.Text;

namespace Quiddity.Support
{
    // https://github.com/mono/mono/blob/main/mcs/class/Mono.Security/Mono.Security/ASN1.cs

    class ASN1
    {
        public byte[] Tag { get; set; }
        public byte[] Length { get; set; }
        public byte[] Value { get; set; }

        public ASN1()
        {
            this.Tag = new byte[1];
            this.Length = new byte[1];
            this.Value = new byte[0];
        }

        public byte[] GetBytes(ASN1 packet)
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(packet.Tag);
                packetWriter.Write(packet.Length);
                packetWriter.Write(packet.Value);
                return memoryStream.ToArray();
            }

        }

        public byte[] GetTagBytes(byte[] data, ref int index, int length, byte tag, out byte tagDecoded)
        {
            tagDecoded = 0x00;
            byte[] value = new byte[0];
            int valueLength;

            while (index < length - 1 && tag != tagDecoded)
            {
                DecodeTag(data, ref index, out tagDecoded, out valueLength, out value);

                if (tagDecoded == 0 || tag == tagDecoded)
                {
                    continue;
                }

                if ((tagDecoded & 0x20) == 0x20)
                {
                    int decodePosistion = index;
                    value = GetTagBytes(data, ref decodePosistion, (decodePosistion + valueLength), tag, out tagDecoded);
                }

                index += valueLength;
            }

            return value;
        }

        public byte GetTag(byte[] data)
        {
            byte tagDecoded;
            byte[] value;
            int valueLength;
            int index = 0;

            DecodeTag(data, ref index, out tagDecoded, out valueLength, out value);
            return tagDecoded;
        }

        public static byte[] GetTagBytes(int tag, byte[] data)
        {
            byte tagDecoded = 0x00;
            int index = 0;
            ASN1 asn1 = new ASN1();
            return asn1.GetTagBytes(data, ref index, data.Length, (byte)tag, out tagDecoded);
        }

        public static byte[] GetTagBytes(int tag, byte[] data, int index)
        {
            byte tagDecoded = 0x00;
            ASN1 asn1 = new ASN1();
            return asn1.GetTagBytes(data, ref index, data.Length, (byte)tag, out tagDecoded);
        }

        public byte[] Decode(byte[] data, ref int index, int length)
        {
            byte tag;
            byte[] value = new byte[0];
            int valueLength;
            int i = 0;

            while (index < length - 1)
            {
                DecodeTag(data, ref index, out tag, out valueLength, out value);

                if (tag == 0)
                {
                    continue;
                }

                if((tag & 0x20) == 0x20)
                {
                    int decodePosistion = index;
                    value = Decode(data, ref decodePosistion, (decodePosistion + valueLength));
                }

                index += valueLength;
                i++;
                
            }

            return value;
        }

        public void DecodeTag(byte[] data, ref int index, out byte tag, out int length, out byte[] value)
        {
            tag = data[index++];
            length = data[index++];

            if ((length & 0x80) == 0x80)
            {
                int lengthCount = length & 0x7f;            
                length = 0;

                for (int i = 0; i < lengthCount; i++)
                {
                    length = length * 256 + data[index++];
                }
               
            }
            
            value = new byte[length];
            Buffer.BlockCopy(data, index, value, 0, length);
        }

        public byte[] Encode(byte tag, byte[] data)
        {
            int dataLength = data.Length;
            this.Tag[0] = tag;

            if (dataLength <= 127)
            {
                this.Length[0] = (byte)dataLength;
            }
            else if (dataLength <= 255)
            {
                this.Length = new byte[2];
                this.Length[0] = 0x81;
                this.Length[1] = (byte)dataLength;
            }
            else if (dataLength > 255)
            {
                this.Length = new byte[3];
                this.Length[0] = 0x82;
                this.Length[1] = (byte)(dataLength >> 8);
                this.Length[2] = (byte)(dataLength);
            }

            return Utilities.BlockCopy(this.Tag, this.Length, data);
        }

        public static byte[] Encode(int tag, byte[] data)
        {
            ASN1 asn1 = new ASN1();
            return asn1.Encode((byte)tag, data);
        }

        public static string[] DecodeOctetStringArray (byte[] data)
        {
            int index = Array.IndexOf<byte>(data, 0x04, 0);
            List<string> list = new List<string>();

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);              

                while (index > -1)
                {
                    memoryStream.Position += 2;
                    list.Add(Encoding.UTF8.GetString(packetReader.ReadBytes(data[index + 1])));
                    index = Array.IndexOf<byte>(data, 0x04, (int)memoryStream.Position);
                }

            }

            return list.ToArray();
        }

        public static int GetLength(int index, byte[] data)
        {
            int length = 0;

            switch (data[index])
            {

                case 0x84:
                    {
                        index++;
                        byte[] lengthData = new byte[4];
                        Buffer.BlockCopy(data, index, lengthData, 0, 4);
                        Array.Reverse(lengthData);
                        length = BitConverter.ToInt32(lengthData, 0);
                        length += 4;
                    }
                    break;

                case 0x83:
                    {
                        index++;
                        byte[] lengthData = new byte[3];
                        Buffer.BlockCopy(data, index, lengthData, 0, 4);
                        Array.Reverse(lengthData);
                        length = BitConverter.ToInt32(lengthData, 0);
                        length += 3;
                    }
                    break;

                case 0x82:
                    {
                        index++;
                        byte[] lengthData = new byte[2];
                        Buffer.BlockCopy(data, index, lengthData, 0, 2);
                        Array.Reverse(lengthData);
                        length = BitConverter.ToInt16(lengthData, 0);
                        length += 2;
                    }
                    break;

                case 0x81:
                    {
                        length = data[index++];
                        length += 3;
                    }
                    break;

                default:
                    length = data[index];
                    length += 2;
                    break;

            }

            return length;
        }

    }

}
