using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Inveigh
{
    class Arguments
    {
        public static void ValidateArguments()
        {

            string[] ynArguments = 
            { 
                nameof(Program.argConsoleUnique),
                nameof(Program.argDHCPv6),               
                nameof(Program.argDNS),
                nameof(Program.argFileOutput),
                nameof(Program.argFileUnique),
                nameof(Program.argHTTP),
                nameof(Program.argHTTPS),
                nameof(Program.argICMPv6),
                nameof(Program.argInspect),
                nameof(Program.argIPv4),
                nameof(Program.argIPv6),
                nameof(Program.argLDAP),
                nameof(Program.argLocal),
                nameof(Program.argLLMNR),
                nameof(Program.argLogOutput),
                nameof(Program.argMachineAccounts),
                nameof(Program.argMDNS),
                nameof(Program.argMDNSUnicast),
                nameof(Program.argNBNS),
                nameof(Program.argProxy),
                nameof(Program.argSniffer),
                nameof(Program.argSMB),          
                nameof(Program.argWebDAV)
            };

            string[] ynArgumentValues =
            { 
                Program.argConsoleUnique,
                Program.argDHCPv6,          
                Program.argDNS,
                Program.argFileOutput,
                Program.argFileUnique,
                Program.argHTTP,
                Program.argHTTPS, 
                Program.argICMPv6,
                Program.argInspect,
                Program.argIPv4,
                Program.argIPv6,
                Program.argLDAP,
                Program.argLocal,
                Program.argLLMNR,
                Program.argLogOutput,
                Program.argMachineAccounts,
                Program.argMDNS,
                Program.argMDNSUnicast,
                Program.argNBNS, 
                Program.argProxy,
                Program.argSniffer,
                Program.argSMB,          
                Program.argWebDAV
            };

            string[] intArguments =
            {
                nameof(Program.argConsole),
                nameof(Program.argConsoleLimit),
                nameof(Program.argConsoleStatus),
                nameof(Program.argDHCPv6TTL),
                nameof(Program.argDNSTTL),
                nameof(Program.argICMPv6Interval),
                nameof(Program.argLLMNRTTL),
                nameof(Program.argMDNSTTL),
                nameof(Program.argNBNSTTL),
                nameof(Program.argProxyPort),
                nameof(Program.argRunCount),
                nameof(Program.argRunTime)
            };

            string[] intArgumentValues =
            {
                Program.argConsole,
                Program.argConsoleLimit,
                Program.argConsoleStatus,
                Program.argDHCPv6TTL,
                Program.argDNSTTL,
                Program.argICMPv6Interval,
                Program.argLLMNRTTL,
                Program.argMDNSTTL,
                Program.argNBNSTTL,
                Program.argProxyPort,
                Program.argRunCount,
                Program.argRunTime
            };

            ValidateStringArguments(ynArguments, ynArgumentValues, new string[] { "Y", "N" });
            ValidateStringArguments(new string[] { nameof(Program.argConsole) }, new string[] { Program.argConsole }, new string[] { "0", "1", "2", "3" });
            string[] authArguments = { nameof(Program.argHTTPAuth), nameof(Program.argProxyAuth), nameof(Program.argWPADAuth), nameof(Program.argWebDAVAuth) };
            string[] authArgumentValues = { Program.argHTTPAuth, Program.argProxyAuth, Program.argWPADAuth, Program.argWebDAVAuth };
            ValidateStringArguments(authArguments, authArgumentValues, new string[] { "ANONYMOUS", "BASIC", "NTLM" });
            ValidateStringArrayArguments(nameof(Program.argDNSTypes), Program.argDNSTypes, new string[] { "A", "SOA", "SRV" });
            ValidateStringArrayArguments(nameof(Program.argDNSSRV), Program.argDNSSRV, new string[] { "LDAP", "KERBEROS", "KPASSWORD", "GC" });
            ValidateStringArrayArguments(nameof(Program.argNBNSTypes), Program.argNBNSTypes, new string[] { "00", "03", "20", "1B", "1C", "1D", "1E" });
            ValidateStringArrayArguments(nameof(Program.argMDNSQuestions), Program.argMDNSQuestions, new string[] { "QM", "QU" });
            ValidateStringArrayArguments(nameof(Program.argMDNSTypes), Program.argMDNSTypes, new string[] { "A", "AAAA", "ANY" });
            ValidateStringArrayArguments(nameof(Program.argLLMNRTypes), Program.argLLMNRTypes, new string[] { "A", "AAAA", "ANY" });
            ValidateIntArguments(intArguments, intArgumentValues);
            string[] ipAddressArguments = { nameof(Program.argSnifferIP), nameof(Program.argSnifferIPv6), nameof(Program.argListenerIP), nameof(Program.argListenerIPv6), nameof(Program.argSpooferIP), nameof(Program.argSpooferIPv6) };
            string[] ipAddressArgumentValues = { Program.argSnifferIP, Program.argSnifferIPv6, Program.argListenerIP, Program.argListenerIPv6, Program.argSpooferIP, Program.argSpooferIPv6 };
            ValidateIPAddressArguments(ipAddressArguments, ipAddressArgumentValues);
            ValidateIntArrayArguments(nameof(Program.argHTTPPorts), Program.argHTTPPorts);
            Regex r = new Regex("^[A-Fa-f0-9]{16}$");
            
            if (!string.IsNullOrEmpty(Program.argChallenge) && !r.IsMatch(Program.argChallenge))
            {
                Console.WriteLine("Challenge is invalid");
                Environment.Exit(0);
            }
            
            r = new Regex("^[A-Fa-f0-9]{12}$");
            
            if (!string.IsNullOrEmpty(Program.argMAC) && !r.IsMatch(Program.argMAC))
            {
                Console.WriteLine("MAC address is invalid");
                Environment.Exit(0);
            }

            if ((Program.argDNSTypes.Contains("SOA") || Program.argDNSTypes.Contains("SRV")) && (string.IsNullOrEmpty(Program.argDNSHost) || Program.argDNSHost.Split('.').Count() < 3))
            { 
                Console.WriteLine("DNSHost must be specified and fully qualified when using DNSTypes SOA or SRV"); Environment.Exit(0);
            }

            if (string.Equals(Program.argFileOutput, "Y") && !Directory.Exists(Program.argFileDirectory))
            {
                Console.WriteLine("FileOutputDirectory is invalid");
                Environment.Exit(0);
            }

        }

        public static void ParseArguments()
        {

            try
            {
                Program.dnsDomain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            catch
            {
                Program.dnsDomain = Program.netbiosDomain;
            }

            Program.console = int.Parse(Program.argConsole);
            Program.consoleQueueLimit = int.Parse(Program.argConsoleLimit);
            Program.consoleStatus = int.Parse(Program.argConsoleStatus);
            Program.icmpv6Interval = int.Parse(Program.argICMPv6Interval);
            Program.runCount = int.Parse(Program.argRunCount);
            Program.runTime = int.Parse(Program.argRunTime);
            if (string.Equals(Program.argConsoleUnique, "Y")) { Program.enabledConsoleUnique = true; }
            if (string.Equals(Program.argFileOutput, "Y")) { Program.enabledFileOutput = true; }
            if (string.Equals(Program.argFileUnique, "Y")) { Program.enabledFileUnique = true; }
            if (string.Equals(Program.argDHCPv6, "Y")) { Program.enabledDHCPv6 = true; }
            if (string.Equals(Program.argDNS, "Y")) { Program.enabledDNS = true; }
            if (string.Equals(Program.argHTTP, "Y")) { Program.enabledHTTP = true; }
            if (string.Equals(Program.argHTTPS, "Y")) { Program.enabledHTTPS = true; }
            if (string.Equals(Program.argICMPv6, "Y")) { Program.enabledICMPv6 = true; }
            if (string.Equals(Program.argInspect, "Y")) { Program.enabledInspect = true; }
            if (string.Equals(Program.argIPv4, "Y")) { Program.enabledIPv4 = true; }
            if (string.Equals(Program.argIPv6, "Y")) { Program.enabledIPv6 = true; }
            if (string.Equals(Program.argLDAP, "Y")) { Program.enabledLDAP = true; }
            if (string.Equals(Program.argLLMNR, "Y")) { Program.enabledLLMNR = true; }
            if (string.Equals(Program.argLogOutput, "Y")) { Program.enabledLogOutput = true; }
            if (string.Equals(Program.argMDNS, "Y")) { Program.enabledMDNS = true; }
            if (string.Equals(Program.argMDNSUnicast, "Y")) { Program.enabledMDNSUnicast = true; }
            if (string.Equals(Program.argProxy, "Y")) { Program.enabledProxy = true; }
            if (string.Equals(Program.argMachineAccounts, "Y")) { Program.enabledMachineAccounts = true; }
            if (string.Equals(Program.argNBNS, "Y")) { Program.enabledNBNS = true; }
            if (string.Equals(Program.argSniffer, "Y")) { Program.enabledSniffer = true; }
            if (!Program.enabledWindows) { Program.enabledSniffer = false; }
            if (string.Equals(Program.argSMB, "Y")) { Program.enabledSMB = true; }
            if (string.Equals(Program.argWebDAV, "Y")) { Program.enabledWebDAV = true; }
            if (string.Equals(Program.argLocal, "Y")) { Program.enabledLocal = true; }
            if (string.Equals(Program.argRepeat, "Y")) { Program.enabledRepeat = true; }

            if (!string.Equals(Program.argListenerIP, "0.0.0.0"))
            {
                Program.listenerIPAddress = IPAddress.Parse(Program.argListenerIP);
            }
            else
            {
                Program.argListenerIP = IPAddress.Any.ToString();
            }

            if (!string.Equals(Program.argListenerIPv6, "::"))
            {
                Program.listenerIPv6Address = IPAddress.Parse(Program.argListenerIPv6);
            }
            else
            {
                Program.argListenerIPv6 = IPAddress.IPv6Any.ToString();
            }

            if (Program.enabledSniffer)
            {

                if (Program.enabledIPv4 && string.IsNullOrEmpty(Program.argSnifferIP))
                {
                    Program.argSnifferIP = GetLocalIPAddress("IPv4");

                    if (string.IsNullOrEmpty(Program.argSnifferIP))
                    {
                        Program.enabledIPv4 = false;
                    }

                }

                if (Program.enabledIPv6 && string.IsNullOrEmpty(Program.argSnifferIPv6))
                {
                    Program.argSnifferIPv6 = GetLocalIPAddress("IPv6");

                    if (string.IsNullOrEmpty(Program.argSnifferIPv6))
                    {
                        Program.enabledIPv6 = false;
                    }

                }

                if (string.IsNullOrEmpty(Program.argSpooferIP))
                {
                    Program.argSpooferIP = Program.argSnifferIP;
                }

                if (string.IsNullOrEmpty(Program.argSpooferIPv6))
                {
                    Program.argSpooferIPv6 = Program.argSnifferIPv6;
                }

            }
            else
            {

                if (string.IsNullOrEmpty(Program.argSpooferIP))
                {

                    if (!string.Equals(Program.argListenerIP, "0.0.0.0"))
                    {
                        Program.argSpooferIP = Program.argListenerIP;
                    }
                    else
                    {
                        Program.argSpooferIP = GetLocalIPAddress("IPv4");

                        if (string.IsNullOrEmpty(Program.argSpooferIP))
                        {
                            Program.enabledIPv4 = false;
                        }

                    }

                }

                if (string.IsNullOrEmpty(Program.argSpooferIPv6))
                {

                    if (!string.Equals(Program.argListenerIPv6, "::"))
                    {
                        Program.argSpooferIPv6 = Program.argListenerIPv6;
                    }
                    else
                    {
                        Program.argSpooferIPv6 = GetLocalIPAddress("IPv6");

                        if (string.IsNullOrEmpty(Program.argSpooferIPv6))
                        {
                            Program.enabledIPv6 = false;
                        }

                    }

                }

            }

            if (string.IsNullOrEmpty(Program.argMAC))
            {

                if (string.IsNullOrEmpty(Program.argSnifferIPv6))
                {
                    Program.argMAC = GetLocalMACAddress(GetLocalIPAddress("IPv6"));
                }
                else
                {
                    Program.argMAC = GetLocalMACAddress(Program.argSnifferIPv6);
                }

            }
            
            Program.argMAC = Program.argMAC.Insert(2, ":").Insert(5, ":").Insert(8, ":").Insert(11, ":").Insert(14, ":");

            if (Program.enabledInspect)
            {

                if (Program.enabledElevated)
                {
                    Program.enabledHTTP = false;
                    Program.enabledProxy = false;
                    Program.enabledSMB = false;
                    Program.enabledICMPv6 = false;
                }
                else
                {
                    Program.enabledHTTP = false;
                    Program.enabledProxy = false;
                }

            }

            if (Program.enabledProxy)
            {
                Program.argWPADResponse = string.Concat("function FindProxyForURL(url,host) {", "return \"PROXY ", Program.argSnifferIP, ":", Program.argProxyPort, "; PROXY ", Program.argSnifferIP, ":", (int.Parse(Program.argProxyPort) + 1).ToString(), "; DIRECT\";}");
            }
            else if (string.IsNullOrEmpty(Program.argWPADResponse))
            {
                Program.argWPADResponse = "function FindProxyForURL(url,host) {return \"DIRECT\";}";
            }
        }

        public static void ValidateStringArguments(string[] arguments, string[] values, string[] validValues)
        {
            int i = 0;
            foreach (string value in values)
            {

                if (!validValues.Contains(value))
                {
                    Console.WriteLine(arguments[i].Substring(3) + " value must be " + string.Join("/", validValues));
                    Environment.Exit(0);
                }

                i++;
            }

        }

        public static void ValidateStringArrayArguments(string argument, string[] values, string[] validValues)
        {

            foreach (string value in values)
            {

                if (!validValues.Contains(value))
                {
                    Console.WriteLine(argument.Substring(3) + " value must be " + string.Join("/", validValues));
                    Environment.Exit(0);
                }

            }

        }

        public static void ValidateIntArguments(string[] arguments, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!string.IsNullOrEmpty(value))
                {

                    try
                    {
                        Int32.Parse(value);

                    }
                    catch
                    {
                        Console.WriteLine(arguments[i].Substring(3) + " value must be an integer");
                        Environment.Exit(0);
                    }

                }

                i++;
            }

        }

        public static void ValidateIntArrayArguments(string argument, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!string.IsNullOrEmpty(value))
                {

                    try
                    {
                        int.Parse(value);

                    }
                    catch
                    {
                        Console.WriteLine(argument.Substring(3) + " values must be integers");
                        Environment.Exit(0);
                    }

                }

                i++;
            }

        }

        public static void ValidateIPAddressArguments(string[] arguments, string[] values)
        {

            int i = 0;
            foreach (string value in values)
            {

                if (!string.IsNullOrEmpty(value))
                {

                    try
                    {
                        IPAddress.Parse(value);

                    }
                    catch
                    {
                        Console.WriteLine(arguments[i].Substring(3) + " value must be an IP address");
                        Environment.Exit(0);
                    }

                }

                i++;
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

    }
}
