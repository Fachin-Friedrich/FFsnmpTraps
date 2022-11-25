using System;
using System.Collections.Generic;
using System.Threading;
using SnmpSharpNet;
using System.Diagnostics;
using csJson;
using System.Net;
using System.IO;

namespace Experimental
{  
    class Program
    {
        static EventLog ELog;
        static Dictionary<int, MIBRecord> MIBRecords = null;

        static void WriteLogSimple( string txt, EventLogEntryType eventtype = EventLogEntryType.Information )
        {
            var col0 = Console.ForegroundColor;
            Console.ForegroundColor = eventtype == EventLogEntryType.Error ? ConsoleColor.Red : col0;
            Console.WriteLine($"[{DateTime.Now}] {txt}");
            Console.ForegroundColor = col0;

            ELog.WriteEntry(
                message: txt,
                type: eventtype
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
            WriteLogSimple("Trap message recieved");
            
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
                WriteLogSimple(e.ToString(), EventLogEntryType.Error);
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

                WriteLogSimple("Eventlog initialized.");
            }
            else
            {
                ELog = new EventLog();
                ELog.Source = logname;
                ELog.Log = logname;

                WriteLogSimple("FFTraps started.");
            }

        }

        static void InitMIBRecords()
        {
            // Currently We only support mib loading by manufacturer

            var file = File.OpenRead("devicemapping.json");
            var buffer = new byte[file.Length];
            file.Read(buffer, 0, (int)file.Length);
            file.Close();

            string raw = System.Text.ASCIIEncoding.UTF8.GetString(buffer);
            var json = jsonRoot.Parse(raw);
            string man = MainboardInfo.Manufacturer;

            var manufacturers = json["ByManufacturer"].Array;
            for( ulong i = 0; i < manufacturers.Elements; ++i)
            {
                var obj = manufacturers[i].Object;
                if( obj["Manufacturer"].String == man)
                {
                    string filepath = obj["File"].String;
                    MIBRecords = MIBParserLite.Parse(filepath);
                    WriteLogSimple($"{filepath} loaded.");
                }
            }

            if( MIBRecords == null)
            {
                throw new Exception($"Failed to match MIB-File for device for manufacturer \"{man}\"");
            }
        }

        static void BeginNetworkService()
        {
            var socket = new System.Net.Sockets.UdpClient(162);
            WriteLogSimple("Listening on port 162");
            while (true)
            {
                var ep = new IPEndPoint(IPAddress.Any, 162);
                var buffer = socket.Receive(ref ep);

                if (buffer.Length > 0)
                {
                    new Thread(() => HandleTrap(buffer, ep)).Start();
                }
                else
                {
                    WriteLogSimple("Zero length trap receieved");
                }
            }
        }

        static void Initialize()
        {
            try
            {
                InitEventLog();
                InitMIBRecords();
                BeginNetworkService();
            }
            catch( Exception e )
            {
                // TODO Terminate Service here
                WriteLogSimple(e.ToString(), EventLogEntryType.Error);
            }
        }

        static void Main()
        {
            Initialize();
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

                    if (buffer.Length > 0)
                    {
                        new Thread(() => HandleTrap(buffer, ep)).Start();
                    }
                    else
                    {
                        WriteLogSimple("Zero length trap receieved");
                    }

                }
                catch (Exception e)
                {
                    WriteLogSimple(e.ToString());
                }

            }
        }

    } // End of class

} // End of namespace
