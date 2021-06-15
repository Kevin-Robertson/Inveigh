using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Linq;
using System.Diagnostics;
using Quiddity.Support;

namespace Inveigh
{
    class Output
    {

        public static void OutputLoop()
        {
            bool keyDetect = true;
            bool keyPressed = false;

            do
            {

                while (Program.enabledConsoleOutput && !keyPressed)
                {

                    try
                    {

                        if (keyDetect && Console.KeyAvailable)
                        {
                            keyPressed = true;
                        }

                    }
                    catch { keyDetect = false; }

                    while (Program.consoleList.Count > 0)
                    {
                        ConsoleOutputFormat(Program.consoleList[0]);
                        Program.consoleList.RemoveAt(0);
                    }

                    if (!Program.isRunning)
                    {
                        break;
                    }

                    Thread.Sleep(5);
                }

            } while (Program.isRunning && Program.enabledConsoleOutput && Console.ReadKey(true).Key != ConsoleKey.Escape);

        }

        public static void Queue(string Output)
        {

            lock (Program.outputList)
            {
                Program.outputList.Add(Output);
            }

        }

        public static void OutputColor(string output, string status, ConsoleColor color)
        {
            string[] split = output.Substring(1).Split('[');
            
            foreach (string segment in split)
            {
                string[] split2 = segment.Split(']');

                int i = 0;
                foreach (string segment2 in split2)
                {
                    int j = 0;
                    if (i % 2 == 0)
                    {
                        string[] split3 = segment2.Split('|');
                        Console.Write("[");
                        
                        foreach (string segment3 in split3)
                        {

                            if (j !=0 && j < split3.Length)
                            {
                                Console.Write("|");
                            }

                            Console.ForegroundColor = color;
                            Console.Write(segment3);
                            Console.ResetColor();                         
                            j++;
                        }

                         Console.Write("]");
                    }
                    else
                    {

                        if (segment2.Contains("\r\n"))
                        {
                            string[] split4 = segment2.Split('\n');

                            if (split4.Length == 2)
                            {
                                Console.Write(split4[0] + "\n");
                                Console.ForegroundColor = color;
                                Console.Write(split4[1]);
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.Write(segment2);
                            }

                        }
                        else
                        {
                            Console.Write(segment2);
                        }

                    }

                    i++;
                }
                

            }

            Console.WriteLine();
        }

        public static void OutputCommand(string description, string[] headings, IList<string> list, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            int padLeft = (Console.WindowWidth - description.Length) / 2;
            int padRight = padLeft;
            int pad = Console.WindowWidth - description.Length - padLeft - padRight;
            padRight += pad;
            Console.Write(" ".PadLeft(padLeft, '='));
            Console.ResetColor();
            Console.Write(description);
            Console.ForegroundColor = color;
            Console.WriteLine(" ".PadRight(padRight, '='));
            Console.ResetColor();
            Console.WriteLine();

            int i = 0;
            foreach (string segment in headings)
            {
                if (i < 3)
                {
                    Console.Write(segment.PadRight(34));
                }
                else if (i == 3)
                {
                    Console.Write(segment);
                }

                i++;
            }

            Console.WriteLine();
            Console.ForegroundColor = color;
            Console.WriteLine("".PadRight(Console.WindowWidth, '='));
            Console.ResetColor();

            if (list.Count > 0)
            {

                foreach (string line in list)
                {
                    string[] split = line.Split(',');
                    i = 0;

                    foreach (string segment in split)
                    {

                        if (i < 3)
                        {
                            Console.Write(segment.PadRight(32));
                        }
                        else if (i == 3)
                        {
                            Console.Write(segment);
                        }

                        if (i < split.Length - 1)
                        {
                            Console.ForegroundColor = color;
                            Console.Write("| ");
                            Console.ResetColor();
                        }

                        i++;
                    }

                    Console.WriteLine();
                }

            }
            else
            {
                Console.WriteLine("No Results");
            }

            Console.WriteLine();
        }

        public static void ConsoleOutputFormat(string consoleEntry)
        {

            if (string.IsNullOrEmpty(consoleEntry))
            {
                consoleEntry = "";
            }

            string entryType = consoleEntry.Substring(1, 1);

            if (entryType.Equals("."))
            {
                Console.WriteLine(consoleEntry);
            }
            else if (entryType.Equals("-"))
            {
                OutputColor(consoleEntry, "-", Program.colorNegative);
            }
            else if (entryType.Equals("+") || consoleEntry.Equals("[redacted]"))
            {
                OutputColor(consoleEntry, "+", Program.colorPositive);
            }
            else if (entryType.Equals("!"))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(consoleEntry);
                Console.ResetColor();
            }
            else if (entryType.Equals("?"))
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine(consoleEntry);
                Console.ResetColor();
            }
            else if (entryType.Equals("*"))
            {
                Console.ForegroundColor = Program.colorPositive;
                Console.WriteLine(consoleEntry);
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine(consoleEntry);
            }

        }

        public static void StartupOutput()
        {
            string address = "Addresses";

            if (!Program.enabledIPv4 || !Program.enabledIPv6)
            {
                address = "Address";
            }

            Queue(string.Format("[*] Inveigh {0} [Started {1} | PID {2}]", Program.version, DateTime.Now.ToString("s"), Process.GetCurrentProcess().Id)); // thanks to @mcorybillington for the pid addition
            if (Program.enabledInspect) { Program.outputList.Add("[+] Inspect Only Mode"); }

            if (Program.enabledSniffer)
            {
                GetStartupMessageIP(string.Concat("Packet Sniffer ", address), Program.argSnifferIP, Program.argSnifferIPv6);
            }
            else
            {
                Queue("[-] Packet Sniffer");
            }

            GetStartupMessageIP(string.Concat("Listener ", address), Program.argListenerIP, Program.argListenerIPv6);
            GetStartupMessageIP(string.Concat("Spoofer Reply ", address), Program.argSpooferIP, Program.argSpooferIPv6);

            string repeat;

            if (Program.enabledRepeat)
            { 
                repeat = "Enabled"; 
            }
            else
            {
                repeat = "Disabled";
            }

            string localAttacks;

            if (Program.enabledLocal)
            {
                localAttacks = "Enabled";
            }
            else
            {
                localAttacks = "Disabled";
            }

            Queue(string.Format("[+] Spoofer Options [Repeat {0} | Local Attacks {1}]", repeat, localAttacks));
            GetStartupMessageUDP("DHCPv6", Program.enabledDHCPv6, null, null, Program.argMAC, Program.argDNSSuffix);
            GetStartupMessageUDP("DNS", Program.enabledDNS, Program.argDNSTypes, null, null, null);

            if (Program.enabledICMPv6)
            {

                if (Program.enabledDHCPv6)
                {
                    Queue(string.Format("[+] ICMPv6 Router Advertisement [Interval {0} Seconds]", Program.argICMPv6Interval));
                }
                else if (!string.IsNullOrEmpty(Program.argDNSSuffix))
                {
                    Queue(string.Format("[+] ICMPv6 Router Advertisement [Option DNS Suffix | Interval {0} Seconds]", Program.argICMPv6Interval));
                }
                else
                {
                    Queue(string.Format("[+] ICMPv6 Router Advertisement [Option DNS | Interval {0} Seconds]", Program.argICMPv6Interval)); // todo check
                }

            }
            else
            {
                Queue("[-] ICMPv6");
            }

            GetStartupMessageUDP("LLMNR", Program.enabledLLMNR, Program.argLLMNRTypes, null, null, null);
            GetStartupMessageUDP("MDNS", Program.enabledMDNS, Program.argMDNSTypes, Program.argMDNSQuestions, null, null);
            GetStartupMessageUDP("NBNS", Program.enabledNBNS, Program.argNBNSTypes, null, null, null);
            GetStartupMessageTCP("HTTP", Program.enabledHTTP, Program.argHTTPAuth, Program.argWPADAuth, Program.argHTTPPorts);
            GetStartupMessageTCP("HTTPS", Program.enabledHTTPS,  Program.argHTTPAuth, Program.argWPADAuth, Program.argHTTPSPorts);
            GetStartupMessageTCP("WebDAV", Program.enabledWebDAV, Program.argWebDAVAuth, null, null);
            GetStartupMessageTCP("Proxy", Program.enabledProxy, Program.argProxyAuth, null, new string[] { Program.argProxyPort });
            GetStartupMessageTCP("LDAP", Program.enabledLDAP, null, null, Program.argLDAPPorts);
            GetStartupMessageTCP("SMB", Program.enabledSMB, null, null, Program.argSMBPorts);
            if (Program.enabledFileOutput) Queue(string.Format("[+] File Output [{0}]", Program.argFileDirectory));
            else Queue("[-] File Output");
            if (Program.isSession) Queue("[+] Previous Session Files [Imported]");
            else Queue("[+] Previous Session Files (Not Found)");
            if (Program.runCount == 1) Program.outputList.Add(string.Format("[+] Run Count [{0} Minute]", Program.runCount));
            else if (Program.runCount > 1) Program.outputList.Add(string.Format("[+] Run Count [{0} Minutes]", Program.runCount));
            if (Program.runTime == 1) Program.outputList.Add(string.Format("[+] Run Time [{0} Minute]", Program.runTime));
            else if (Program.runTime > 1) Program.outputList.Add(string.Format("[+] Run Time [{0} Minutes]", Program.runTime));
            Queue("[*] Press ESC to enter/exit interactive console");
        }

        public static void GetStartupMessageIP(string ipType, string address1, string address2)
        {
            string startupMessage = "";
            string optionStatus = "-";

            if (Program.enabledIPv4 && !string.IsNullOrEmpty(address1) && Program.enabledIPv6 && !string.IsNullOrEmpty(address2))
            {
                optionStatus = "+";
                startupMessage = string.Format("[{0}] {1} [IP {2} | IPv6 {3}]", optionStatus, ipType, address1, address2);
            }
            else if (Program.enabledIPv4 && !string.IsNullOrEmpty(address1))
            {
                optionStatus = "+";
                startupMessage = string.Format("[{0}] {1} [IP {2}]", optionStatus, ipType, address1);
            }
            else if (Program.enabledIPv6 && !string.IsNullOrEmpty(address2))
            {
                optionStatus = "+";
                startupMessage = string.Format("[{0}] {1} [IPv6 {2}]", optionStatus, ipType, address2);
            }
            else
            {
                startupMessage = string.Format("[{0}] {1}", optionStatus, ipType);
            }

            Queue(startupMessage);
        }

        public static void GetStartupMessageUDP(string protocol, bool enabled, string[] recordTypes, string[] mdnsQuestions, string option1, string option2)
        {
            string startupMessage;
            string optionType = "Listener";
            string optionStatus = "-";
            string types;
            string typesHeader = "Type";
            string questions;
            string questionsHeader = "Question";

            if (Program.enabledSniffer)
            {
                optionType = "Packet Sniffer";
            }

            if (!Utilities.ArrayIsNullOrEmpty(recordTypes) && recordTypes.Length > 1)
            {
                typesHeader = "Types";
            }

            if (!Utilities.ArrayIsNullOrEmpty(mdnsQuestions) && mdnsQuestions.Length > 1)
            {
                questionsHeader = "Questions";
            }

            if (enabled)
            {
                optionStatus = "+";

                if (!Utilities.ArrayIsNullOrEmpty(mdnsQuestions) && !Utilities.ArrayIsNullOrEmpty(recordTypes))
                {
                    types = string.Join(":", recordTypes);
                    questions = string.Join(":", mdnsQuestions);
                    startupMessage = string.Format("[{0}] {1} {2} [{3} {4} | {5} {6}]", optionStatus, protocol, optionType, questionsHeader, questions, typesHeader, types);
                }
                else if (!Utilities.ArrayIsNullOrEmpty(recordTypes))
                {
                    types = string.Join(":", recordTypes);
                    startupMessage = string.Format("[{0}] {1} {2} [{3} {4}]", optionStatus, protocol, optionType, typesHeader, types);
                }
                else if (protocol.Equals("DHCPv6"))
                {

                    if (string.IsNullOrEmpty(option2))
                    {
                        startupMessage = string.Format("[{0}] {1} {2} [MAC {3}]", optionStatus, protocol, optionType, option1);
                    }
                    else
                    {
                        startupMessage = string.Format("[{0}] {1} {2} [MAC {3} | DNS Suffix {4}]", optionStatus, protocol, optionType, option1, option2);
                    }

                }
                else
                {
                    startupMessage = string.Format("[{0}] {1} {2}", optionStatus, protocol, optionType);
                }

            }
            else
            {
                startupMessage = string.Format("[{0}] {1}", optionStatus, protocol);
            }

            Queue(startupMessage);
        }

        public static void GetStartupMessageTCP(string protocol, bool enabled, string auth1, string auth2, string[] ports)
        {
            string startupMessage = "";
            string optionType = "Listener";
            string optionStatus = "-";
            string portHeading = "Port";

            if (Program.enabledSniffer && protocol.StartsWith("SMB"))
            {
                optionType = "Packet Sniffer";
            }

            if (enabled)
            {
                optionStatus = "+";

                if (!Utilities.ArrayIsNullOrEmpty(ports))
                {

                    if (ports.Length > 1)
                    {
                        portHeading = "Ports";
                    }

                    if (protocol.StartsWith("HTTP"))
                    {
                        startupMessage = string.Format("[{0}] {1} {2} [HTTPAuth {3} | WPADAuth {4} | {5} {6}]", optionStatus, protocol, optionType, auth1, auth2, portHeading, string.Join(":", ports));
                    }
                    else if (protocol.StartsWith("Proxy"))
                    {
                        startupMessage = string.Format("[{0}] {1} {2} [ProxyAuth {3} | {4} {5}]", optionStatus, protocol, optionType, auth1, portHeading, string.Join(":", ports));
                    }
                    else
                    {
                        startupMessage = string.Format("[{0}] {1} {2} [{3} {4}]", optionStatus, protocol, optionType, portHeading, string.Join(":", ports));
                    }

                }
                else if (string.Equals(protocol, "WebDAV"))
                {
                    startupMessage = string.Format("[{0}] {1} [WebDAVAuth {2}]", optionStatus, protocol, auth1);
                }

            }
            else
            {
                startupMessage = string.Format("[{0}] {1}", optionStatus, protocol);
            }

            Queue(startupMessage);
        }

        public static void NTLMOutput(string user, string domain, string challenge, string ntlmResponse, string sourceIP, string host, string protocol, string protocolPort, string sourcePort, string lmResponse)
        {
            string challengeResponse;
            bool isNTLMv2 = false;
            bool isNULL = false;
            string version = "NTLMv1";

            if (ntlmResponse.Length > 48)
            {
                isNTLMv2 = true;
                version = "NTLMv2";
            }
            else if (ntlmResponse.Length == 0)
            {
                isNULL = true;
            }

            if (isNTLMv2)
            {
                challengeResponse = user + "::" + domain + ":" + challenge + ":" + ntlmResponse.Insert(32, ":");
            }
            else
            {
                challengeResponse = user + "::" + domain + ":" + lmResponse + ":" + ntlmResponse + ":" + challenge;
            }

            if (Program.enabledMachineAccounts || (!Program.enabledMachineAccounts && !user.EndsWith("$")))
            {

                if (!string.IsNullOrEmpty(challenge))
                {

                    if (!isNULL)
                    {
                        string capture = string.Concat(sourceIP, ",", host, ",", domain, "\\", user);
                        bool isUnique = false;

                        if (isNTLMv2 && Program.ntlmv2UsernameList.Any(str => str.Contains(capture)) || (!isNTLMv2 && Program.ntlmv1UsernameList.Any(str => str.Contains(capture))))
                        {
                            isUnique = true;
                        }

                        if (Program.enabledConsoleUnique && isUnique)
                        {
                            Queue(string.Format("[+] [{0}] {1}({2}) {3} captured for [{4}\\{5}] from {6}({7}):{8} [not unique]", Timestamp(), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
                        }
                        else
                        {
                            Queue(string.Format("[+] [{0}] {1}({2}) {3} captured for [{4}\\{5}] from {6}({7}):{8}:\r\n{9}", Timestamp(), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort, challengeResponse));
                        }

                        if (isNTLMv2)
                        {

                            if (Program.enabledFileOutput && (!Program.enabledFileUnique || !isUnique))
                            {

                                lock (Program.ntlmv2FileList)
                                {
                                    Program.ntlmv2FileList.Add(challengeResponse);
                                }

                                Queue(string.Format("[!] [{0}] {1}({2}) {3} for [{4}\\{5}] written to {6}", Timestamp(), protocol, protocolPort, version, domain, user, string.Concat(Program.argFilePrefix, "-NTLMv2.txt")));
                            }

                            if (!isUnique)
                            {

                                lock (Program.ntlmv2UniqueList)
                                {
                                    Program.ntlmv2UniqueList.Add(challengeResponse);
                                }

                                lock (Program.ntlmv2UsernameList)
                                {
                                    Program.ntlmv2UsernameList.Add(string.Concat(sourceIP, ",", host, ",", domain, "\\", user, ",", challenge));
                                }

                                lock (Program.ntlmv2UsernameFileList)
                                {
                                    Program.ntlmv2UsernameFileList.Add(string.Concat(sourceIP, ",", host, ",", domain, "\\", user, ",", challenge));
                                }

                                lock (Program.IPCaptureList)
                                {
                                    Program.IPCaptureList.Add(string.Concat(host));
                                }

                                lock (Program.HostCaptureList)
                                {
                                    Program.HostCaptureList.Add(string.Concat(host));
                                }

                            }

                            lock (Program.ntlmv2List)
                            {
                                Program.ntlmv2List.Add(challengeResponse);
                            }

                        }
                        else
                        {

                            if (Program.enabledFileOutput && (!Program.enabledFileUnique || !isUnique))
                            {

                                lock (Program.ntlmv1FileList)
                                {
                                    Program.ntlmv1FileList.Add(challengeResponse);
                                }

                                Queue(string.Format("[+] [{0}] {1}({2}) {3} for [{4}\\{5}] written to {6}", Timestamp(), protocol, protocolPort, version, domain, user, string.Concat(Program.argFilePrefix, "-NTLMv1.txt")));
                            }

                            if (!isUnique)
                            {

                                lock (Program.ntlmv1UniqueList)
                                {
                                    Program.ntlmv1UniqueList.Add(challengeResponse);
                                }

                                lock (Program.ntlmv1UsernameList)
                                {
                                    Program.ntlmv1UsernameList.Add(string.Concat(sourceIP, ",", host, ",", domain, "\\", user, ",", challenge));
                                }

                                lock (Program.ntlmv1UsernameFileList)
                                {
                                    Program.ntlmv1UsernameFileList.Add(string.Concat(sourceIP, ",", host, ",", domain, "\\", user, ",", challenge));
                                }

                                lock (Program.IPCaptureList)
                                {
                                    Program.IPCaptureList.Add(string.Concat(host));
                                }

                                lock (Program.HostCaptureList)
                                {
                                    Program.HostCaptureList.Add(string.Concat(host));
                                }

                            }

                            lock (Program.ntlmv1List)
                            {
                                Program.ntlmv1List.Add(challengeResponse);
                            }

                        }

                    }
                    else
                    {
                        Queue(string.Format("[.] [{0}] {1}({2}) NTLM null response from {5}({6}):{7}", Timestamp(), protocol, protocolPort, domain, user, sourceIP, host, sourcePort));
                    }

                }
                else
                {
                    Queue(string.Format("[!] [{0}] {1}({2}) {3} challenge missing for {4}\\{5} from {6}({7}):{8}:", Timestamp(), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
                    Queue(challengeResponse);
                }

            }
            else
            {
                Queue(string.Format("[-] [{0}] {1}({2}) {3} ignored for {4}\\{5} from {6}({7}):{8} [machine account]", Timestamp(), protocol, protocolPort, version, domain, user, sourceIP, host, sourcePort));
            }

        }

        public static void FileOutput()
        {

            while (Program.isRunning)
            {

                try
                {
                    ProcessFileOutput();
                }
                catch (Exception ex)
                {
                    Queue(string.Format("[-] [{0}] File output error detected - {1}", Timestamp(), ex));
                }

                Thread.Sleep(200);
            }

        }

        public static void SpooferOutput(string protocol, string type, string request, string clientIP, string outputMessage)
        {
            string status = "-";

            if (outputMessage.Equals("response sent"))
            {
                status = "+";
            }

            Queue(string.Format("[{0}] [{1}] {2}({3}) request [{4}] from {5} [{6}]", status, Timestamp(), protocol, type, request, clientIP, outputMessage));
        }

        public static void DHCPv6Output(int msgType, string leaseIP, string clientIP, string clientMAC, string clientHostname, string message)
        {
            string responseStatus = "-";

            if (string.Equals(message, "response sent"))
            {
                responseStatus = "+";
            }

            string responseType = "";
            string responseAction = "";

            switch (msgType)
            {
                case 1:
                    responseType = "solicitation";
                    responseAction = "advertised";
                    break;

                case 3:
                    {
                        responseType = "request";
                        responseAction = "leased";
                    }
                    break;

                case 5:
                    {
                        responseType = "renew";
                        responseAction = "renewed";
                    }
                    break;
            }

            if (msgType == 3 || msgType == 5 && !Program.dhcpv6List.Contains(clientHostname + "," + clientIP + "," + leaseIP))
            {
                Program.dhcpv6List.Add(clientHostname + "," + clientMAC + "," + leaseIP);
            }

            if (!string.IsNullOrEmpty(clientHostname))
            {
                Output.Queue(string.Format("[{0}] [{1}] DHCPv6 [{2}] from {3}({4}) [{5}]", responseStatus, Output.Timestamp(), responseType, clientIP, clientHostname, message));
            }
            else
            {
                Output.Queue(string.Format("[{0}] [{1}] DHCPv6 [{2}] from {3} [{4}]", responseStatus, Output.Timestamp(), responseType, clientIP, message));
            }

            if (string.Equals(message, "response sent"))
            {
                Output.Queue(string.Format("[{0}] [{1}] DHCPv6 [{2}] {3} to [{4}]", responseStatus, Output.Timestamp(), leaseIP, responseAction, clientMAC));
            }
            else
            {
                Output.Queue(string.Format("[{0}] [{1}] DHCPv6 client MAC [{2}]", responseStatus, Output.Timestamp(), clientMAC));
            }

        }

        public static string Timestamp()
        {
            return DateTime.Now.ToString("HH:mm:ss");
        }

        public static void OutputHelp(string argument, string description)
        {
            int pad = 15;
            Console.Write("  -" + argument.PadRight(pad));
            Console.WriteLine(description);
            Console.WriteLine();
        }

        public static void GetHelp(string arg)
        {
            bool nullarg = true;

            Console.WriteLine();

            if (nullarg)
            {
                Console.WriteLine("Control:");
                Console.WriteLine("");
            }

            if (nullarg || string.Equals(arg, "INSPECT"))
            {
                string argument = "Inspect";
                string description = "Default=Disabled: (Y/N) inspect traffic only.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "IPV4"))
            {
                string argument = "IPv4";
                string description = "Default=Enabled: (Y/N) IPv4 spoofing/capture.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "IPV6"))
            {
                string argument = "IPv6";
                string description = "Default=Enabled: (Y/N) IPv6 spoofing/capture.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "RUNCOUNT"))
            {
                string argument = "RunCount";
                string description = "Default=Unlimited: Number of NetNTLM captures to perform before auto-exiting.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "RUNTIME"))
            {
                string argument = "RunTime";
                string description = "Default=Unlimited: Run time duration in minutes.";
                OutputHelp(argument, description);
            }

            if (nullarg)
            {
                Console.WriteLine("");
                Console.WriteLine("Output:");
                Console.WriteLine("");
            }

            if (nullarg || string.Equals(arg, "CONSOLE"))
            {
                string argument = "Console";
                string description = "Default=3: Set the level for console output. (0=none, 1=only captures/spoofs, 2=no informational, 3=all)";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "CONSOLELIMIT"))
            {
                string argument = "ConsoleLimit";
                string description = "Default=Unlimited: Limit to queued console entries.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "CONSOLESTATUS"))
            {
                string argument = "ConsoleStatus";
                string description = "Default=Disabled: Interval in minutes for auto-displaying capture details.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "CONSOLEUNIQUE"))
            {
                string argument = "ConsoleUnique";
                string description = "Default=Enabled: (Y/N) displaying only unique (user and system combination) hashes at time of capture.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "FILEDIRECTORY"))
            {
                string argument = "FileDirectory";
                string description = "Default=Working Directory: Valid path to an output directory for enabled file output.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "FILEOUTPUT"))
            {
                string argument = "FileOutput";
                string description = "Default=Disabled: (Y/N) real time file output.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "FILEPREFIX"))
            {
                string argument = "FilePrefix";
                string description = "Default=Inveigh: Prefix for all output files.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "FILEUNIQUE"))
            {
                string argument = "FileUnique";
                string description = "Default=Enabled: (Y/N) outputting only unique (user and system combination) hashes.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LOGOUTPUT"))
            {
                string argument = "LogOutput";
                string description = "Default=Disabled: (Y/N) outputting log entries.";
                OutputHelp(argument, description);
            }

            if (nullarg)
            {
                Console.WriteLine();
                Console.WriteLine("Spoofers:");
                Console.WriteLine("");
            }

            if (nullarg || string.Equals(arg, "DHCPV6"))
            {
                string argument = "DHCPV6";
                string description = "Default=Disabled: (Y/N) DHCPv6 spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "DHCPV6TTL"))
            {
                string argument = "DHCPv6TTL";
                string description = "Default=300: Lease lifetime in seconds.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "DNS"))
            {
                string argument = "DNS";
                string description = "Default=Enabled: (Y/N) DNS spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "DNSHOST"))
            {
                string argument = "DNSHost";
                string description = "Fully qualified hostname to use SOA/SRV responses.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "DNSSRV"))
            {
                string argument = "DNSSRV";
                string description = "Default=LDAP: Comma separated list of SRV request services to answer.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "DNSSUFFIX"))
            {
                string argument = "DNSSuffix";
                string description = "DNS search suffix to include in DHCPv6/ICMPv6 packets.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "DNSTTL"))
            {
                string argument = "DNSTTL";
                string description = "Default=30: DNS TTL in seconds.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "DNSTYPES"))
            {
                string argument = "DNSTYPES";
                string description = "Default=A: (A, SOA, SRV) Comma separated list of DNS types to spoof.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "ICMPV6"))
            {
                string argument = "ICMPv6";
                string description = "Default=Enabled: (Y/N) sending ICMPv6 RAs for DHCPv6, secondary IPv6 DNS, or DNS search suffix.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "ICMPV6INTERVAL"))
            {
                string argument = "ICMPv6Interval";
                string description = "Default=200: ICMPv6 RA interval in seconds.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "IGNOREDOMAINS"))
            {
                string argument = "IgnoreDomains";
                string description = "Default=None: Comma separated list of domains to ignore when spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "IGNOREHOSTS"))
            {
                string argument = "IgnoreHosts";
                string description = "Default=None: Comma separated list of hostnames to ignore when spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "IGNOREIPS"))
            {
                string argument = "IgnoreIPs";
                string description = "Default=Local: Comma separated list of source IP addresses to ignore when spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "IGNOREMACS"))
            {
                string argument = "IgnoreMACs";
                string description = "Default=Local: Comma separated list of MAC addresses to ignore when DHCPv6 spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LOCAL"))
            {
                string argument = "Local";
                string description = "Default=Disabled: (Y/N) performing spoofing attacks against the host system.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LLMNR"))
            {
                string argument = "LLMNR";
                string description = "Default=Enabled: (Y/N) LLMNR spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LLMNRTTL"))
            {
                string argument = "LLMNRTTL";
                string description = "Default=30: LLMNR TTL in seconds.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "MAC"))
            {
                string argument = "MAC";
                string description = "Local MAC address for DHCPv6.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "MDNS"))
            {
                string argument = "MDNS";
                string description = "Default=Enabled: (Y/N) mDNS spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "MDNSQuestions"))
            {
                string argument = "MDNSQuestions";
                string description = "Default=QU,QM: Comma separated list of question types to spoof. (QU,QM)";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "MDNSTTL"))
            {
                string argument = "MDNSTTL";
                string description = "Default=120: mDNS TTL in seconds.";
                OutputHelp(argument, description);
            }        

            if (nullarg || string.Equals(arg, "MDNSTYPES"))
            {
                string argument = "MDNSTypes";
                string description = "Default=A: Comma separated list of mDNS record types to spoof. (A,AAAA,ANY)";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "MDNSUNICAST"))
            {
                string argument = "MDNSUnicast";
                string description = "Default=Enabled: (Y/N) sending a unicast only response to a QM request.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "NBNS"))
            {
                string argument = "NBNS";
                string description = "Default=Disabled: (Y/N) NBNS spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "NBNSTTL"))
            {
                string argument = "NBNSTTL";
                string description = "Default=165: NBNS TTL in seconds.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "NBNSTYPES"))
            {
                string argument = "NBNSTypes";
                string description = "Default=00,20: Comma separated list of NBNS types to spoof. (00,03,20,1B)";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "REPLYTODOMAINS"))
            {
                string argument = "ReplyToDomains";
                string description = "Default=All: Comma separated list of domains to respond to when spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "REPLYTOHOSTS"))
            {
                string argument = "ReplyToHosts";
                string description = "Default=All: Comma separated list of hostnames to respond to when spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "REPLYTOIPS"))
            {
                string argument = "ReplyToIPs";
                string description = "Default=All: Comma separated list of source IP addresses to respond to when spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "REPLYTOMACS"))
            {
                string argument = "ReplyToMACs";
                string description = "Default=All: Comma separated list of MAC addresses to respond to when DHCPv6 spoofing.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "SPOOFERIP"))
            {
                string argument = "SpooferIP";
                string description = "Default=Autoassign: IP address included in spoofing responses.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "SPOOFERIPV6"))
            {
                string argument = "SpooferIPv6";
                string description = "Default=Autoassign: IPv6 address included in spoofing responses.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "REPEAT"))
            {
                string argument = "Repeat";
                string description = "Default=Enabled: (Y/N) repeated spoofing attacks against a system after NetNTLM capture.";
                OutputHelp(argument, description);
            }

            if (nullarg)
            {
                Console.WriteLine();
                Console.WriteLine("Capture:");
                Console.WriteLine("");
            }

            if (nullarg || string.Equals(arg, "CERT"))
            {
                string argument = "Cert";
                string description = "Base64 certificate for TLS.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "CERTPASSWORD"))
            {
                string argument = "CertPassword";
                string description = "Base64 certificate password for TLS.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "CHALLENGE"))
            {
                string argument = "Challenge";
                string description = "Default=Random per request: 16 character hex NetNTLM challenge for use with the TCP listeners.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "HTTP"))
            {
                string argument = "HTTP";
                string description = "Default=Enabled: (Y/N) HTTP listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "HTTPAUTH"))
            {
                string argument = "HTTPAuth";
                string description = "Default=NTLM: (Anonymous/Basic/NTLM) HTTP/HTTPS listener authentication.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "HTTPPORTS"))
            {
                string argument = "HTTPPorts";
                string description = "Default=80: Comma seperated list of TCP ports for the HTTP listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "HTTPREALM"))
            {
                string argument = "HTTPRealm";
                string description = "Default=ADFS: Basic authentication realm.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "HTTPRESPONSE"))
            {
                string argument = "HTTPResponse";
                string description = "Content to serve as the default HTTP/HTTPS/Proxy response.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "HTTPS"))
            {
                string argument = "HTTPS";
                string description = "Default=Enabled: (Y/N) HTTPS listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "HTTPSPORTS"))
            {
                string argument = "HTTPSPorts";
                string description = "Default=443: Comma separated list of TCP ports for the HTTPS listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "IGNOREAGENTS"))
            {
                string argument = "IgnoreAgents";
                string description = "Default=Firefox: Comma separated list of HTTP user agents to ignore with wpad anmd proxy auth.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LDAP"))
            {
                string argument = "LDAP";
                string description = "Default=Enabled: (Y/N) LDAP listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LDAPPORTS"))
            {
                string argument = "LDAPPorts";
                string description = "Default=389: Comma separated list of TCP ports for the LDAP listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LISTENERIP"))
            {
                string argument = "ListenerIP";
                string description = "Default=Any: IP address for all listeners.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "LISTENERIPV6"))
            {
                string argument = "ListenerIPv6";
                string description = "Default=Any: IPv6 address for all listeners.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "MACHINES"))
            {
                string argument = "Machines";
                string description = "Default=Disabled: (Y/N) machine account NetNTLM captures.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "PROXY"))
            {
                string argument = "Proxy";
                string description = "Default=Disabled: (Y/N) proxy listener authentication captures.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "PROXYAUTH"))
            {
                string argument = "ProxyAuth";
                string description = "Default=NTLM: (Basic/NTLM) Proxy authentication.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "PROXYPORT"))
            {
                string argument = "ProxyPort";
                string description = "Default=8492: Port for the proxy listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "SMB"))
            {
                string argument = "SMB";
                string description = "Default=Enabled: (Y/N) SMB sniffer/listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "SMBPORTS"))
            {
                string argument = "SMBPorts";
                string description = "Default=445: Port for the SMB listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "SNIFFERIP"))
            {
                string argument = "SnifferIP";
                string description = "Default=Autoassign: IP address included in spoofing responses.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "SNIFFERIPV6"))
            {
                string argument = "SnifferIPv6";
                string description = "Default=Autoassign: IPv6 address included in spoofing responses.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "WEBDAV"))
            {
                string argument = "WebDAV";
                string description = "Default=Enabled: (Y/N) serving WebDAV over HTTP/HTTPS listener.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "WEBDAVAUTH"))
            {
                string argument = "WebDAVAuth";
                string description = "Default=NTLM: (Anonymous/Basic/NTLM) WebDAV authentication.";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "WPADAUTH"))
            {
                string argument = "WPADAuth ";
                string description = "Default=Enabled: (Y/N) authentication type for wpad.dat requests. (Anonymous/Basic/NTLM)";
                OutputHelp(argument, description);
            }

            if (nullarg || string.Equals(arg, "WPADRESPONSE"))
            {
                string argument = "WPADResponse";
                string description = "Default=Autogenerated: Contents of wpad.dat responses.";
                OutputHelp(argument, description);
            }

            Console.WriteLine();
        }

        public static void ProcessOutput()
        {

            while (Program.outputList.Count > 0)
            {
                if (Program.console == 3)
                {
                    Program.consoleList.Add(Program.outputList[0]);
                }

                if (Program.console == 2 && (Program.outputList[0].StartsWith("[*]") || Program.outputList[0].StartsWith("[+]") || Program.outputList[0].StartsWith("[-]") || !Program.outputList[0].StartsWith("[")))
                {
                    Program.consoleList.Add(Program.outputList[0]);
                }

                if (Program.console == 1 && (Program.outputList[0].StartsWith("[*]") || Program.outputList[0].StartsWith("[+]") || !Program.outputList[0].StartsWith("[")))
                {
                    Program.consoleList.Add(Program.outputList[0]);
                }

                if (Program.enabledLogOutput)
                {
                    Program.logList.Add(Program.outputList[0]);
                }

                if (Program.outputList[0].Contains(" captured for ") && !Program.outputList[0].EndsWith("[not unique]"))
                {
                    Program.logFileList.Add(string.Concat(Program.outputList[0].Split('\n')[0].Replace(":\r"," "), "[redacted]"));
                }
                else
                {
                    Program.logFileList.Add(Program.outputList[0]);
                }

                lock (Program.outputList)
                {
                    Program.outputList.RemoveAt(0);
                }

            }

            if (!Program.enabledConsoleOutput && Program.consoleQueueLimit >= 0)
            {

                while (Program.consoleList.Count > Program.consoleQueueLimit && !Program.enabledConsoleOutput)
                {
                    Program.consoleList.RemoveAt(0);
                }

            }

        }

        public static void ProcessFileOutput()
        {

            while (Program.logFileList.Count > 0)
            {

                using (StreamWriter outputFileLog = new StreamWriter(Path.Combine(Program.argFileDirectory, string.Concat(Program.argFilePrefix, "-Log.txt")), true))
                {
                    outputFileLog.WriteLine(Program.logFileList[0]);
                    outputFileLog.Close();

                    lock (Program.logFileList)
                    {
                        Program.logFileList.RemoveAt(0);
                    }

                }

            }

            while (Program.cleartextFileList.Count > 0)
            {

                using (StreamWriter outputFileCleartext = new StreamWriter(Path.Combine(Program.argFileDirectory, string.Concat(Program.argFilePrefix, "-Cleartext.txt")), true))
                {
                    outputFileCleartext.WriteLine(Program.cleartextFileList[0]);
                    outputFileCleartext.Close();

                    lock (Program.cleartextFileList)
                    {
                        Program.cleartextFileList.RemoveAt(0);
                    }

                }

            }

            while (Program.ntlmv1FileList.Count > 0)
            {

                using (StreamWriter outputFileNTLMv1 = new StreamWriter(Path.Combine(Program.argFileDirectory, string.Concat(Program.argFilePrefix, "-NTLMv1.txt")), true))
                {
                    outputFileNTLMv1.WriteLine(Program.ntlmv1FileList[0]);
                    outputFileNTLMv1.Close();

                    lock (Program.ntlmv1FileList)
                    {
                        Program.ntlmv1FileList.RemoveAt(0);
                    }

                }

            }

            while (Program.ntlmv2FileList.Count > 0)
            {

                using (StreamWriter outputFileNTLMv2 = new StreamWriter(Path.Combine(Program.argFileDirectory, string.Concat(Program.argFilePrefix, "-NTLMv2.txt")), true))
                {
                    outputFileNTLMv2.WriteLine(Program.ntlmv2FileList[0]);
                    outputFileNTLMv2.Close();

                    lock (Program.ntlmv2FileList)
                    {
                        Program.ntlmv2FileList.RemoveAt(0);
                    }

                }

            }

            while (Program.ntlmv1UsernameFileList.Count > 0)
            {

                using (StreamWriter outputUsernameFileNTLMv1 = new StreamWriter(Path.Combine(Program.argFileDirectory, string.Concat(Program.argFilePrefix, "-NTLMv1Users.txt")), true))
                {
                    outputUsernameFileNTLMv1.WriteLine(Program.ntlmv1UsernameFileList[0]);
                    outputUsernameFileNTLMv1.Close();

                    lock (Program.ntlmv1UsernameList)
                    {
                        Program.ntlmv1UsernameFileList.RemoveAt(0);
                    }

                }

            }

            while (Program.ntlmv2UsernameFileList.Count > 0)
            {

                using (StreamWriter outputUsernameFileNTLMv2 = new StreamWriter(Path.Combine(Program.argFileDirectory, string.Concat(Program.argFilePrefix, "-NTLMv2Users.txt")), true))
                {
                    outputUsernameFileNTLMv2.WriteLine(Program.ntlmv2UsernameFileList[0]);
                    outputUsernameFileNTLMv2.Close();

                    lock (Program.ntlmv2UsernameFileList)
                    {
                        Program.ntlmv2UsernameFileList.RemoveAt(0);
                    }

                }

            }

        }

    }
}
