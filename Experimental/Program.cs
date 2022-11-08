using System;
using System.Collections.Generic;
using System.Threading;
using SnmpSharpNet;
using System.Diagnostics;
using csJson;
using System.Net;

namespace Experimental
{  
    class Program
    {
        static EventLog ELog;

        static void WriteLogSimple( string txt)
        {
            Console.WriteLine($"[{DateTime.Now}] {txt}");
            ELog.WriteEntry(
                message: txt,
                type: EventLogEntryType.Information,
                eventID: -1,
                category: -1
            );
        }

        static void WriteEvent( IPHostEntry host, SnmpV2Packet pkt, byte[] raw)
        {
            string hostname = string.IsNullOrEmpty(host.HostName) ? string.Empty : $" ({host.HostName})";
            var output = new System.Text.StringBuilder();

            output.AppendLine("SNMP v2");
            output.AppendLine($"Agent address: {host.AddressList[0]}{hostname}");
            output.AppendLine($"Community: {pkt.Community}");
            output.AppendLine($"Message count: {pkt.Pdu.VbList.Count}");
            output.AppendLine("---");
            foreach (var v in pkt.Pdu.VbList)
            {
                output.AppendLine($"{v.Oid} - {SnmpConstants.GetTypeName(v.Value.Type)} : {v.Value}");
            }

            string result = output.ToString();
            Console.WriteLine($"[{DateTime.Now}] {result}");
            ELog.WriteEntry(
                message: result,
                type: EventLogEntryType.Warning,
                eventID: pkt.Pdu.ErrorIndex,
                category: (short) pkt.Pdu.ErrorStatus,
                rawData: raw
            );
        }

        static void WriteEvent( IPHostEntry host, TrapPdu data, byte[] raw)
        {
            var output = new System.Text.StringBuilder();
            string hostname = string.IsNullOrEmpty(host.HostName) ? string.Empty : $" ({host.HostName})";

            output.AppendLine($"SNMP v1");
            output.AppendLine($"Generic: {data.Generic} - Specific: {data.Specific}");
            output.AppendLine($"Agent address: {host.AddressList[0]}{hostname}");
            output.AppendLine($"Message count: {data.VbList.Count}");
            output.AppendLine("---");
            foreach (var v in data.VbList)
            {
                output.AppendLine($"{v.Oid} - {SnmpConstants.GetTypeName(v.Value.Type)} : {v.Value}");
            }

            string result = output.ToString();
            Console.WriteLine($"[{DateTime.Now}] {result}");
            ELog.WriteEntry(
                message: result,
                type: EventLogEntryType.Warning,
                eventID: data.Specific,
                category: (short) data.Generic,
                rawData: raw
            );
        }

        static void HandleTrap( byte[] raw, IPEndPoint ep )
        {
            try
            {
                int version = SnmpPacket.GetProtocolVersion(raw, raw.Length);
                var hostinfo = System.Net.Dns.GetHostEntry(ep.Address);
                switch (version)
                {
                    case (int)SnmpVersion.Ver1:

                        var pkt1 = new SnmpV1TrapPacket();
                        pkt1.decode(raw, raw.Length);
                        WriteEvent(hostinfo, pkt1.TrapPdu, raw);
                        break;

                    case (int)SnmpVersion.Ver2:

                        var pkt2 = new SnmpV2Packet();
                        pkt2.decode(raw, raw.Length);
                        if (pkt2.Pdu.Type != PduType.V2Trap)
                        {
                            throw new Exception("Captured corrupted SNMP V2 Package");
                        }

                        WriteEvent(hostinfo, pkt2, raw);
                        break;

                    default:
                        throw new Exception($"Unsupported SNMP version: {version}");
                }
            }
            catch( Exception e)
            {
                WriteLogSimple(e.ToString());
            }
        }
        
        static void InitEventLog()
        {
            string logname = "FFTrapLog";

            if( !EventLog.Exists(logname))
            {
                EventLog.CreateEventSource(logname, logname);

                ELog = new EventLog();
                ELog.Source = logname;
                ELog.Log = logname;

                ELog.WriteEntry(
                    "Eventlog initialized",
                    EventLogEntryType.Information,
                    0
                );
            }
            else
            {
                ELog = new EventLog();
                ELog.Source = logname;
                ELog.Log = logname;

                ELog.WriteEntry(
                    "FFTraps started",
                    EventLogEntryType.Information,
                    1
                );
            }

        }

        static void SelfIdentify()
        {
            Console.WriteLine(MainboardInfo.Model);
            Console.WriteLine(MainboardInfo.Manufacturer);
            Console.WriteLine(MainboardInfo.Product);
            Console.WriteLine(MainboardInfo.SerialNumber);
            Console.WriteLine(MainboardInfo.SystemName);
        }

        static void TestParsing()
        {
            var x = MIBParserLite.Parse(@"C:\Daten\cs2\FFsnmpTraps\mib\ASUS_PETTrap.mib");
            Console.WriteLine(x.Count);
        }

        static void Main_dns_check()
        {
            var z = System.Net.Dns.GetHostEntry("192.168.25.200");
            Console.WriteLine(z.HostName);
            for( int i = 0; i < z.Aliases.Length; ++i)
            {
                Console.WriteLine($"[{i}] {z.Aliases[i]}");
            }
        }

        static void Main_Networkloop(string[] args)
        {
            var socket = new System.Net.Sockets.UdpClient(162);

            while (true)
            {
                try
                {
                    var ep = new IPEndPoint(IPAddress.Any, 162);
                    var buffer = socket.Receive(ref ep);

                    if( buffer.Length > 0)
                    {
                        new Thread(() => HandleTrap(buffer, ep)).Start();
                    }
                    else
                    {
                        WriteLogSimple("Zero length trap receieved");
                    }

                }
                catch( Exception e )
                {
                    WriteLogSimple(e.ToString());
                }

            }
        }

    } // End of class

} // End of namespace
