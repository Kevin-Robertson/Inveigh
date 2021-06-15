using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Net;
using System.Collections.Generic;
using System.Text;
using System.Globalization;

namespace Inveigh
{
    class Control
    {

        public static void ControlLoop(string consoleLevel, int consoleQueueLimit, int consoleStatus, int runCount, int runTime)
        {
            Stopwatch stopwatchConsoleStatus = new Stopwatch();
            stopwatchConsoleStatus.Start();
            Stopwatch stopwatchRunTime = new Stopwatch();
            stopwatchRunTime.Start();
            bool isPromptRefresh = false;

            while (Program.isRunning)
            {

                if (Program.cleartextList.Count > Program.cleartextCount)
                {
                    Program.cleartextCount = Program.cleartextList.Count;
                    Program.isCleartextUpdated = true;
                    isPromptRefresh = true;
                }

                if (Program.ntlmv1List.Count > Program.ntlmv1Count)
                {
                    Program.ntlmv1Count = Program.ntlmv1List.Count;
                    Program.isNTLMv1Updated = true;
                    isPromptRefresh = true;
                }

                if (Program.ntlmv2List.Count > Program.ntlmv2Count)
                {
                    Program.ntlmv2Count = Program.ntlmv2List.Count;
                    Program.isNTLMv2Updated = true;
                    isPromptRefresh = true;
                }

                IList<string> cleartextUnique = Shell.GetUnique(Program.cleartextList, false);

                if (cleartextUnique.Count > Program.cleartextUniqueCount)
                {
                    Program.cleartextUniqueCount = cleartextUnique.Count;
                    Program.isCleartextUniqueUpdated = true;
                    isPromptRefresh = true;
                }

                if (Program.ntlmv1UniqueList.Count > Program.ntlmv1UniqueCount)
                {
                    Program.ntlmv1UniqueCount = Program.ntlmv1UniqueList.Count;
                    Program.isNTLMv1UniqueUpdated = true;
                    isPromptRefresh = true;
                }

                if (Program.ntlmv2UniqueList.Count > Program.ntlmv2UniqueCount)
                {
                    Program.ntlmv2UniqueCount = Program.ntlmv2UniqueList.Count;
                    Program.isNTLMv2UniqueUpdated = true;
                    isPromptRefresh = true;
                }

                if (isPromptRefresh && !Program.enabledConsoleOutput)
                {
                    Shell.RefreshCurrentLine();
                    isPromptRefresh = false;
                }
                else
                {
                    isPromptRefresh = false;
                }

                if (consoleStatus > 0 && Program.enabledConsoleOutput && stopwatchConsoleStatus.Elapsed.Minutes >= consoleStatus)
                {
                    Shell.GetCleartextUnique("");
                    Shell.GetNTLMv1Unique("");
                    Shell.GetNTLMv1Usernames("");
                    Shell.GetNTLMv2Unique("");
                    Shell.GetNTLMv2Usernames("");
                    stopwatchConsoleStatus.Reset();
                    stopwatchConsoleStatus.Start();
                }

                if (runTime > 0 && Program.enabledConsoleOutput && stopwatchRunTime.Elapsed.Minutes >= runTime)
                {                   
                    Output.Queue(String.Format("[*] {0} Inveigh is exiting due to reaching run time", Output.Timestamp()));
                    StopInveigh();
                }

                if (runCount > 0 && Program.enabledConsoleOutput && (Program.ntlmv1List.Count >= runCount || Program.ntlmv2List.Count >= runCount))
                {
                    Output.Queue(String.Format("[*] {0} Inveigh is exiting due to reaching run count", Output.Timestamp()));
                    StopInveigh();
                }

                try
                {
                    Output.ProcessOutput();
                }
                catch (Exception ex)
                {
                    Output.Queue(String.Format("[-] [{0}] Output error detected - {1}", Output.Timestamp(), ex.ToString()));
                }

                Thread.Sleep(5);
            }

        }

        public static void StopInveigh()
        {           
            Program.consoleList.Clear();
            Program.enabledConsoleOutput = true;
            Output.Queue(String.Format("[+] Inveigh exited at {0}", DateTime.Now.ToString("s")));
            Output.ProcessOutput();
            Output.ProcessFileOutput();
            Program.isRunning = false;

            while (Program.consoleList.Count > 0)
            {
                Output.ConsoleOutputFormat(Program.consoleList[0]);
                Program.consoleList.RemoveAt(0);
            }

        }

        public static void ImportSession()
        {

            if (Program.enabledLogOutput && File.Exists(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-Log.txt"))))
            {
                Program.isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-Log.txt")));

                foreach (string line in file)
                {
                    Program.logList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-Cleartext.txt"))))
            {
                Program.isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-Cleartext.txt")));

                foreach (string line in file)
                {
                    Program.cleartextList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv1Users.txt"))))
            {
                Program.isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv1Users.txt")));

                foreach (string line in file)
                {
                    Program.ntlmv1UsernameList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv2Users.txt"))))
            {
                Program.isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv2Users.txt")));

                foreach (string line in file)
                {
                    Program.ntlmv2UsernameList.Add(line);
                }

            }

            if (File.Exists(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv1.txt"))))
            {
                Program.isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv1.txt")));

                foreach (string line in file)
                {
                    Program.ntlmv1List.Add(line);
                }

                Program.ntlmv1UniqueList = Shell.GetUniqueNTLM(Program.ntlmv1List, Program.ntlmv1UsernameList);
            }

            if (File.Exists(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv2.txt"))))
            {
                Program.isSession = true;
                string[] file = File.ReadAllLines(Path.Combine(Program.argFileDirectory, String.Concat(Program.argFilePrefix, "-NTLMv2.txt")));

                foreach (string line in file)
                {
                    Program.ntlmv2List.Add(line);
                }

                Program.ntlmv2UniqueList = Shell.GetUniqueNTLM(Program.ntlmv2List, Program.ntlmv2UsernameList);
            }

            foreach (string entry in Program.ntlmv1UsernameList)
            {
                string[] capture = entry.Split(',');

                if (capture.Length >= 2)
                {
                    Program.IPCaptureList.Add(capture[0]);
                    Program.HostCaptureList.Add(capture[1]);
                }

            }

            foreach (string entry in Program.ntlmv2UsernameList)
            {
                string[] capture = entry.Split(',');

                if (capture.Length >= 2)
                {
                    Program.IPCaptureList.Add(capture[0]);
                    Program.HostCaptureList.Add(capture[1]);
                }

            }

            Program.cleartextCount = Program.cleartextList.Count;
            Program.ntlmv1Count = Program.ntlmv1List.Count;
            Program.ntlmv2Count = Program.ntlmv2List.Count;
            Program.cleartextUniqueCount = Shell.GetUnique(Program.cleartextList, false).Count;
            Program.ntlmv1UniqueCount = Shell.GetUniqueNTLM(Program.ntlmv1List, Program.ntlmv1UsernameList).Count;
            Program.ntlmv2UniqueCount = Shell.GetUniqueNTLM(Program.ntlmv2List, Program.ntlmv2UsernameList).Count;
        }

        public static void StartThreads()
        {

            if (Program.enabledSniffer)
            {

                if (Program.enabledIPv4)
                {

                    if (Program.enabledDNS || Program.enabledMDNS || Program.enabledLLMNR || Program.enabledNBNS || Program.enabledSMB)
                    {
                        Thread snifferSpooferThread = new Thread(() => Sniffer.Start("IP", Program.argSnifferIP, false));
                        snifferSpooferThread.Start();
                    }

                }

                if (Program.enabledIPv6)
                {

                    if (Program.enabledDHCPv6 || Program.enabledDNS || Program.enabledLLMNR || Program.enabledMDNS)
                    {
                        Thread snifferSpooferIPv6Thread = new Thread(() => Sniffer.Start("UDP", Program.argSnifferIPv6, true));
                        snifferSpooferIPv6Thread.Start();
                    }

                    if (Program.enabledSMB)
                    {
                        Thread snifferSpooferIPv6TCPThread = new Thread(() => Sniffer.Start("TCP", Program.argSnifferIPv6, true));
                        snifferSpooferIPv6TCPThread.Start();
                    }

                }

            }
            else
            {

                if (Program.enabledIPv4)
                {

                    if (Program.enabledDNS)
                    {
                        DNSListener dnsListener = new DNSListener(uint.Parse(Program.argDNSTTL), Program.argDNSHost);
                        Thread dnsListenerThread = new Thread(() => dnsListener.Start(IPAddress.Parse(Program.argListenerIP), Program.argSpooferIP, Program.argSpooferIPv6));
                        dnsListenerThread.Start();
                    }

                    if (Program.enabledLLMNR)
                    {
                        LLMNRListener llmnrListener = new LLMNRListener(uint.Parse(Program.argLLMNRTTL));
                        Thread llmnrListenerThread = new Thread(() => llmnrListener.Start(IPAddress.Parse(Program.argListenerIP), Program.argSpooferIP, Program.argSpooferIPv6));
                        llmnrListenerThread.Start();
                    }

                    if (Program.enabledMDNS)
                    {
                        MDNSListener mdnsListener = new MDNSListener(uint.Parse(Program.argMDNSTTL), Program.enabledMDNSUnicast);
                        Thread mdnsListenerThread = new Thread(() => mdnsListener.Start(IPAddress.Parse(Program.argListenerIP), Program.argSpooferIP, Program.argSpooferIPv6));
                        mdnsListenerThread.Start();
                    }

                    if (Program.enabledNBNS)
                    {
                        NBNSListener nbnsListener = new NBNSListener(uint.Parse(Program.argNBNSTTL));
                        Thread nbnsListenerThread = new Thread(() => nbnsListener.Start(IPAddress.Parse(Program.argListenerIP), Program.argSpooferIP, Program.argSpooferIPv6));
                        nbnsListenerThread.Start();
                    }

                    if (Program.enabledSMB)
                    {
                        SMBListener smbListener = new SMBListener();
                        Thread smbListenerThread = new Thread(() => smbListener.Start(IPAddress.Parse(Program.argListenerIP), 445));
                        smbListenerThread.Start();
                    }

                }             

                if (Program.enabledIPv6)
                {

                    if (Program.enabledDHCPv6)
                    {
                        DHCPv6Listener dhcpV6Listener = new DHCPv6Listener(uint.Parse(Program.argDHCPv6TTL), Program.argDNSSuffix);
                        Thread dhcpv6ListenerThread = new Thread(() => dhcpV6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), Program.argMAC, Program.argSpooferIPv6));
                        dhcpv6ListenerThread.Start();
                    }

                    if (Program.enabledDNS)
                    {
                        DNSListener dnsV6Listener = new DNSListener(uint.Parse(Program.argDNSTTL), Program.argDNSHost);
                        Thread dnsV6ListenerThread = new Thread(() => dnsV6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), Program.argSpooferIP, Program.argSpooferIPv6));
                        dnsV6ListenerThread.Start();
                    }

                    if (Program.enabledLLMNR)
                    {
                        LLMNRListener llmnrV6Listener = new LLMNRListener(uint.Parse(Program.argLLMNRTTL));
                        Thread llmnrV6ListenerThread = new Thread(() => llmnrV6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), Program.argSpooferIP, Program.argSpooferIPv6));
                        llmnrV6ListenerThread.Start();
                    }

                    if (Program.enabledMDNS)
                    {
                        MDNSListener mdnsV6Listener = new MDNSListener(uint.Parse(Program.argMDNSTTL), Program.enabledMDNSUnicast);
                        Thread mdnsV6ListenerThread = new Thread(() => mdnsV6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), Program.argSpooferIP, Program.argSpooferIPv6));
                        mdnsV6ListenerThread.Start();
                    }

                    if (Program.enabledSMB)
                    {
                        SMBListener smbv6Listener = new SMBListener();
                        Thread smbv6ListenerThread = new Thread(() => smbv6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), 445));
                        smbv6ListenerThread.Start();
                    }

                }

            }

            if (!Program.enabledInspect)
            {

                if (Program.enabledIPv4)
                {

                    if (Program.enabledHTTP)
                    {

                        foreach (string port in Program.argHTTPPorts)
                        {
                            HTTPListener httpListener = new HTTPListener();
                            Thread httpListenerThread = new Thread(() => httpListener.Start(IPAddress.Parse(Program.argListenerIP), Int32.Parse(port), "HTTP"));
                            httpListenerThread.Start();
                        }

                    }

                    if (Program.enabledHTTPS)
                    {

                        foreach (string port in Program.argHTTPSPorts)
                        {
                            HTTPListener httpsListener = new HTTPListener();
                            Thread httpsListenerThread = new Thread(() => httpsListener.Start(IPAddress.Parse(Program.argListenerIP), Int32.Parse(port), "HTTPS"));
                            httpsListenerThread.Start();
                        }

                    }

                    if (Program.enabledLDAP)
                    {

                        foreach (string port in Program.argLDAPPorts)
                        {
                            LDAPListener ldapListener = new LDAPListener();
                            Thread ldapListenerThread = new Thread(() => ldapListener.Start(IPAddress.Parse(Program.argListenerIP), Int32.Parse(port)));
                            ldapListenerThread.Start();
                        }

                    }

                    if (Program.enabledProxy)
                    {
                        HTTPListener proxyListener = new HTTPListener();
                        Thread proxyListenerThread = new Thread(() => proxyListener.Start(IPAddress.Parse(Program.argListenerIP), Int32.Parse(Program.argProxyPort), "Proxy"));
                        proxyListenerThread.Start();
                    }

                }

                if (Program.enabledIPv6)
                {


                    if (Program.enabledLDAP)
                    {

                        foreach (string port in Program.argLDAPPorts)
                        {
                            LDAPListener ldapv6Listener = new LDAPListener();
                            Thread ldapv6ListenerThread = new Thread(() => ldapv6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), Int32.Parse(port)));
                            ldapv6ListenerThread.Start();
                        }

                    }

                    if (Program.enabledHTTP)
                    {

                        foreach (string port in Program.argHTTPPorts)
                        {
                            HTTPListener httpv6Listener = new HTTPListener();
                            Thread httpv6ListenerThread = new Thread(() => httpv6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), Int32.Parse(port), "HTTPv6"));
                            httpv6ListenerThread.Start();
                        }

                    }

                    if (Program.enabledHTTPS)
                    {

                        foreach (string port in Program.argHTTPPorts)
                        {
                            HTTPListener httpsv6Listener = new HTTPListener();
                            Thread httpsv6ListenerThread = new Thread(() => httpsv6Listener.Start(IPAddress.Parse(Program.argListenerIPv6), Int32.Parse(port), "HTTPSv6"));
                            httpsv6ListenerThread.Start();
                        }

                    }

                    if (Program.enabledICMPv6) // todo check linux
                    {
                        ICMPv6Socket icmpV6Socket = new ICMPv6Socket();
                        Thread icmpv6Thread = new Thread(() => icmpV6Socket.Start());
                        icmpv6Thread.Start();
                    }

                }

            }        

            Thread controlThread = new Thread(() => ControlLoop(Program.argConsole, Program.consoleQueueLimit, Program.consoleStatus, Program.runCount, Program.runTime));
            controlThread.Start();

            if (Program.enabledFileOutput)
            {
                Thread fileOutputThread = new Thread(() => Output.FileOutput());
                fileOutputThread.Start();
            }

        }

    }

}
