/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2022, Kevin Robertson
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
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Quiddity.Support
{
    class Utilities
    {

        public static byte[] BlockCopy(byte[] Data1, byte[] Data2)
        {
            byte[] data = new byte[Data1.Length + Data2.Length];
            Buffer.BlockCopy(Data1, 0, data, 0, Data1.Length);
            Buffer.BlockCopy(Data2, 0, data, Data1.Length, Data2.Length);
            return data;
        }

        public static byte[] BlockCopy(byte[] Data1, byte[] Data2, byte[] Data3)
        {
            byte[] data = new byte[Data1.Length + Data2.Length + Data3.Length];
            Buffer.BlockCopy(Data1, 0, data, 0, Data1.Length);
            Buffer.BlockCopy(Data2, 0, data, Data1.Length, Data2.Length);
            Buffer.BlockCopy(Data3, 0, data, (Data1.Length + Data2.Length), Data3.Length);
            return data;
        }

        public static byte[] BlockCopy(byte[] Data1, byte[] Data2, byte[] Data3, byte[] Data4)
        {
            byte[] data = new byte[Data1.Length + Data2.Length + Data3.Length + Data4.Length];
            Buffer.BlockCopy(Data1, 0, data, 0, Data1.Length);
            Buffer.BlockCopy(Data2, 0, data, Data1.Length, Data2.Length);
            Buffer.BlockCopy(Data3, 0, data, (Data1.Length + Data2.Length), Data3.Length);
            Buffer.BlockCopy(Data4, 0, data, (Data1.Length + Data2.Length + Data3.Length), Data4.Length);
            return data;
        }

        public static bool ArrayIsNullOrEmpty(Array array)
        {
            return (array == null || array.Length == 0);
        }

        public static ushort DataToUInt16(byte[] data)
        {
            return BitConverter.ToUInt16(data, 0);
        }

        public static byte[] GetDNSNameBytes(string name, bool addByte)
        {
            var indexList = new List<int>();

            for (int i = name.IndexOf('.'); i > -1; i = name.IndexOf('.', i + 1))
            {
                indexList.Add(i);
            }

            using (MemoryStream nameMemoryStream = new MemoryStream())
            {
                string nameSection = "";
                int nameStart = 0;

                if (indexList.Count > 0)
                {
                    int nameEnd = 0;

                    foreach (int index in indexList)
                    {
                        nameEnd = index - nameStart;
                        nameMemoryStream.Write(BitConverter.GetBytes(nameEnd), 0, 1);
                        nameSection = name.Substring(nameStart, nameEnd);
                        nameMemoryStream.Write(Encoding.UTF8.GetBytes(nameSection), 0, nameSection.Length);
                        nameStart = index + 1;
                    }

                }

                nameSection = name.Substring(nameStart);
                nameMemoryStream.Write(BitConverter.GetBytes(nameSection.Length), 0, 1);
                nameMemoryStream.Write(Encoding.UTF8.GetBytes(nameSection), 0, nameSection.Length);

                if (addByte)
                {
                    nameMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                }

                return nameMemoryStream.ToArray();
            }

        }

        public static string GetLocalIPAddress(string ipVersion)
        {

            List<string> ipAddressList = new List<string>();
            AddressFamily addressFamily;

            if (string.Equals(ipVersion, "IPv4"))
            {
                addressFamily = AddressFamily.InterNetwork;
            }
            else
            {
                addressFamily = AddressFamily.InterNetworkV6;
            }

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == addressFamily)
                        {
                            ipAddressList.Add(ip.Address.ToString());
                        }

                    }

                }

            }

            return ipAddressList.FirstOrDefault();
        }

        public static string GetLocalMACAddress(string ipAddress)
        {
            List<string> macAddressList = new List<string>();

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == AddressFamily.InterNetworkV6 && string.Equals(ip.Address.ToString(), ipAddress))
                        {
                            macAddressList.Add(networkInterface.GetPhysicalAddress().ToString());
                        }

                    }

                }

            }

            return macAddressList.FirstOrDefault();
        }

        public static int GetNetworkInterfaceIndex(string ipAddress)
        {
            int index = 0;

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == AddressFamily.InterNetworkV6 && string.Equals(ip.Address.ToString(), ipAddress))
                        {
                            index = networkInterface.GetIPProperties().GetIPv6Properties().Index;
                            break;
                        }
                        else if (ip.Address.AddressFamily == AddressFamily.InterNetwork && string.Equals(ip.Address.ToString(), ipAddress))
                        {
                            index = networkInterface.GetIPProperties().GetIPv4Properties().Index;
                            break;
                        }

                    }

                }

            }

            return index;
        }

        public static bool ValidateStringArguments(string[] arguments, string[] values, string[] validValues)
        {
            int i = 0;
            foreach (string value in values)
            {

                if (!validValues.Contains(value))
                {
                    Console.WriteLine(arguments[i].Substring(3) + " value must be " + string.Join("/", validValues));
                    return false;
                }

                i++;
            }

            return true;
        }

        public static bool ValidateStringArrayArguments(string argument, string[] values, string[] validValues)
        {

            foreach (string value in values)
            {

                if (!validValues.Contains(value))
                {
                    Console.WriteLine(argument.Substring(3) + " value must be " + string.Join("/", validValues));
                    return false;
                }

            }

            return true;
        }

        public static bool ValidateIntArguments(string[] arguments, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!string.IsNullOrEmpty(value))
                {

                    try
                    {
                        Int32.Parse(value);
                        return true;

                    }
                    catch
                    {
                        Console.WriteLine(arguments[i].Substring(3) + " value must be an integer");
                        return false;
                    }

                }

                i++;
            }

            return true;
        }

        public static bool ValidateIntArrayArguments(string argument, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!string.IsNullOrEmpty(value))
                {

                    try
                    {
                        int.Parse(value);
                        return true;

                    }
                    catch
                    {
                        Console.WriteLine(argument.Substring(3) + " values must be integers");
                        return false;
                    }

                }

                i++;
            }

            return true;
        }

        public static bool ValidateIPAddressArguments(string[] arguments, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!string.IsNullOrEmpty(value))
                {

                    try
                    {
                        IPAddress.Parse(value);
                        return true;

                    }
                    catch
                    {
                        Console.WriteLine(arguments[i].Substring(3) + " value must be an IP address");
                        return false;
                    }

                }

                i++;
            }

            return true;
        }

    }

}
