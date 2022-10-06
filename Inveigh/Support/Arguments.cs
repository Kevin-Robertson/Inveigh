using Quiddity.Support;
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
        public static bool ValidateArguments()
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
                nameof(Program.argMachineAccount),
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
                Program.argMachineAccount,
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
                nameof(Program.argICMPv6TTL),
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
                Program.argICMPv6TTL,
                Program.argLLMNRTTL,
                Program.argMDNSTTL,
                Program.argNBNSTTL,
                Program.argProxyPort,
                Program.argRunCount,
                Program.argRunTime
            };

            bool allValid = true;
            allValid &= Utilities.ValidateStringArguments(ynArguments, ynArgumentValues, new string[] { "Y", "N" });
            allValid &= Utilities.ValidateStringArguments(new string[] { nameof(Program.argConsole) }, new string[] { Program.argConsole }, new string[] { "0", "1", "2", "3", "4", "5" });
            string[] authArguments = { nameof(Program.argHTTPAuth), nameof(Program.argProxyAuth), nameof(Program.argWPADAuth), nameof(Program.argWebDAVAuth) };
            string[] authArgumentValues = { Program.argHTTPAuth, Program.argProxyAuth, Program.argWPADAuth, Program.argWebDAVAuth };
            allValid &= Utilities.ValidateStringArguments(authArguments, authArgumentValues, new string[] { "ANONYMOUS", "BASIC", "NTLM" });
            allValid &= Utilities.ValidateStringArrayArguments(nameof(Program.argDNSTypes), Program.argDNSTypes, new string[] { "A", "AAAA", "SOA", "SRV" });
            allValid &= Utilities.ValidateStringArrayArguments(nameof(Program.argDNSSRV), Program.argDNSSRV, new string[] { "LDAP", "KERBEROS", "KPASSWORD", "GC" });
            allValid &= Utilities.ValidateStringArrayArguments(nameof(Program.argNBNSTypes), Program.argNBNSTypes, new string[] { "00", "03", "20", "1B", "1C", "1D", "1E" });
            allValid &= Utilities.ValidateStringArrayArguments(nameof(Program.argMDNSQuestions), Program.argMDNSQuestions, new string[] { "QM", "QU" });
            allValid &= Utilities.ValidateStringArrayArguments(nameof(Program.argMDNSTypes), Program.argMDNSTypes, new string[] { "A", "AAAA", "ANY" });
            allValid &= Utilities.ValidateStringArrayArguments(nameof(Program.argLLMNRTypes), Program.argLLMNRTypes, new string[] { "A", "AAAA", "ANY" });
            allValid &= Utilities.ValidateIntArguments(intArguments, intArgumentValues);
            string[] ipAddressArguments = { nameof(Program.argSnifferIP), nameof(Program.argSnifferIPv6), nameof(Program.argListenerIP), nameof(Program.argListenerIPv6), nameof(Program.argSpooferIP), nameof(Program.argSpooferIPv6) };
            string[] ipAddressArgumentValues = { Program.argSnifferIP, Program.argSnifferIPv6, Program.argListenerIP, Program.argListenerIPv6, Program.argSpooferIP, Program.argSpooferIPv6 };
            allValid &= Utilities.ValidateIPAddressArguments(ipAddressArguments, ipAddressArgumentValues);
            allValid &= Utilities.ValidateIntArrayArguments(nameof(Program.argHTTPPorts), Program.argHTTPPorts);
            Regex r = new Regex("^[A-Fa-f0-9]{16}$");
            
            if (!string.IsNullOrEmpty(Program.argChallenge) && !r.IsMatch(Program.argChallenge))
            {
                Console.WriteLine("Challenge is invalid");
                allValid = false;
            }
            
            r = new Regex("^[A-Fa-f0-9]{12}$");
            
            if (!string.IsNullOrEmpty(Program.argMAC) && !r.IsMatch(Program.argMAC))
            {
                Console.WriteLine("MAC address is invalid");
                allValid = false;
            }

            if ((Program.argDNSTypes.Contains("SOA") || Program.argDNSTypes.Contains("SRV")) && (string.IsNullOrEmpty(Program.argDNSHost) || Program.argDNSHost.Split('.').Count() < 3))
            { 
                Console.WriteLine("DNSHost must be specified and fully qualified when using DNSTypes SOA or SRV");
                allValid = false;
            }

            if (string.Equals(Program.argFileOutput, "Y") && !Directory.Exists(Program.argFileDirectory))
            {
                Console.WriteLine("FileOutputDirectory is invalid");
                allValid = false;
            }

            return allValid;
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
            if (string.Equals(Program.argMachineAccount, "Y")) { Program.enabledMachineAccountCapture = true; }
            if (string.Equals(Program.argNBNS, "Y")) { Program.enabledNBNS = true; }
            if (string.Equals(Program.argSniffer, "Y")) { Program.enabledSniffer = true; }
            if (!Program.enabledWindows) { Program.enabledSniffer = false; }
            if (string.Equals(Program.argSMB, "Y")) { Program.enabledSMB = true; }
            if (string.Equals(Program.argWebDAV, "Y") && (string.Equals(Program.argHTTP, "Y") || string.Equals(Program.argHTTPS, "Y"))) { Program.enabledWebDAV = true; }
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
                    Program.argSnifferIP = Utilities.GetLocalIPAddress("IPv4");

                    if (string.IsNullOrEmpty(Program.argSnifferIP))
                    {
                        Program.enabledIPv4 = false;
                    }

                }

                if (Program.enabledIPv6 && string.IsNullOrEmpty(Program.argSnifferIPv6))
                {
                    Program.argSnifferIPv6 = Utilities.GetLocalIPAddress("IPv6");

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
                        Program.argSpooferIP = Utilities.GetLocalIPAddress("IPv4");

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
                        Program.argSpooferIPv6 = Utilities.GetLocalIPAddress("IPv6");

                        if (string.IsNullOrEmpty(Program.argSpooferIPv6))
                        {
                            Program.enabledIPv6 = false;
                        }

                    }

                }

            }

            if (!Program.enabledIPv4)
            {

                Program.argDNSTypes = Program.argDNSTypes.Where(element => element != "A").ToArray();

                if (Utilities.ArrayIsNullOrEmpty(Program.argDNSTypes))
                {
                    Program.argDNSTypes = new string[] { "AAAA" };
                }

                Program.argLLMNRTypes = Program.argLLMNRTypes.Where(element => element != "A").ToArray();

                if (Utilities.ArrayIsNullOrEmpty(Program.argLLMNRTypes))
                {
                    Program.argLLMNRTypes = new string[] { "AAAA" };
                }

                Program.argMDNSTypes = Program.argMDNSTypes.Where(element => element != "A").ToArray();

                if (Utilities.ArrayIsNullOrEmpty(Program.argMDNSTypes))
                {
                    Program.argMDNSTypes = new string[] { "AAAA" };
                }

            }

            if (!Program.enabledIPv6)
            {

                Program.argDNSTypes = Program.argDNSTypes.Where(element => element != "AAAA").ToArray();

                if (Utilities.ArrayIsNullOrEmpty(Program.argDNSTypes))
                {
                    Program.argDNSTypes = new string[] { "A" };
                }

                Program.argLLMNRTypes = Program.argLLMNRTypes.Where(element => element != "AAAA").ToArray();

                if (Utilities.ArrayIsNullOrEmpty(Program.argLLMNRTypes))
                {
                    Program.argLLMNRTypes = new string[] { "A" };
                }

                Program.argMDNSTypes = Program.argMDNSTypes.Where(element => element != "AAAA").ToArray();

                if (Utilities.ArrayIsNullOrEmpty(Program.argMDNSTypes))
                {
                    Program.argMDNSTypes = new string[] { "A" };
                }

            }

            if (Program.enabledIPv6)
            {

                if (string.IsNullOrEmpty(Program.argMAC))
                {

                    if (string.IsNullOrEmpty(Program.argSnifferIPv6))
                    {
                        Program.argMAC = Utilities.GetLocalMACAddress(Utilities.GetLocalIPAddress("IPv6"));
                    }
                    else
                    {
                        Program.argMAC = Utilities.GetLocalMACAddress(Program.argSnifferIPv6);
                    }

                }

                Program.argMAC = Program.argMAC.Insert(2, ":").Insert(5, ":").Insert(8, ":").Insert(11, ":").Insert(14, ":");
            }

            if (!string.IsNullOrEmpty(Program.argSnifferIP))
            {
                Program.networkInterfaceIndexIPv4 = Utilities.GetNetworkInterfaceIndex(Program.argSniffer);
            }

            if (!string.IsNullOrEmpty(Program.argSnifferIPv6))
            {
                Program.networkInterfaceIndexIPv6 = Utilities.GetNetworkInterfaceIndex(Program.argSnifferIPv6);
            }

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

    }

}
