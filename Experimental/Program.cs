using System;
using System.Collections.Generic;
using System.Threading;
using SnmpSharpNet;
using System.Diagnostics;

namespace Experimental
{  
    class Program
    {
        static EventLog ELog;

        static void WriteLogSimple( string txt)
        {
            Console.WriteLine($"[{DateTime.Now}] {txt}");
            ELog.WriteEntry(txt);
        }

        static void HandleV1Trap( byte[] raw)
        {
            var output = new System.Text.StringBuilder();
            var pkt = new SnmpV1TrapPacket();
            pkt.decode(raw, raw.Length);

            output.AppendLine($"SNMP v1");
            output.AppendLine($"Generic: {pkt.Pdu.Generic} - Specific: {pkt.Pdu.Specific}");
            output.AppendLine($"Agent address: {pkt.Pdu.AgentAddress}");
            output.AppendLine($"Message count: {pkt.Pdu.VbList.Count}");
            output.AppendLine("---");
            foreach( var v in pkt.Pdu.VbList)
            {
                output.AppendLine($"{v.Oid} - {SnmpConstants.GetTypeName(v.Value.Type)} : {v.Value.ToString()}");
            }

            string result = output.ToString();
            WriteLogSimple(result);
        }

        static void HandleV2Trap( byte[] raw)
        {
            var pkt = new SnmpV2Packet();
            pkt.decode(raw, raw.Length);
            if( pkt.Pdu.Type != PduType.V2Trap)
            {
                throw new Exception("Captured corrupted SNMP V2 Package");
            }

            var output = new System.Text.StringBuilder();
            output.AppendLine("SNMP v2");
            output.AppendLine($"Community: {pkt.Community}");
            output.AppendLine($"Message count: {pkt.Pdu.VbList.Count}");
            output.AppendLine("---");
            foreach( var v in pkt.Pdu.VbList)
            {
                output.AppendLine($"{v.Oid} - {SnmpConstants.GetTypeName(v.Value.Type)} : {v.Value.ToString()}");
            }

            string result = output.ToString();
            WriteLogSimple(result);
        }

        static void HandleTrap( byte[] raw)
        {
            try
            {
                int version = SnmpPacket.GetProtocolVersion(raw, raw.Length);
                switch (version)
                {
                    case (int)SnmpVersion.Ver1:

                        HandleV1Trap(raw);
                        break;

                    case (int)SnmpVersion.Ver2:

                        HandleV2Trap(raw);
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

        static void Main(string[] args)
        {
            TestParsing();
            return;
            InitEventLog();
            var socket = new System.Net.Sockets.UdpClient(162);

            while (true)
            {
                try
                {
                    var ep = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 162);
                    var buffer = socket.Receive(ref ep);

                    if( buffer.Length > 0)
                    {
                        new Thread(() => HandleTrap(buffer)).Start();
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
