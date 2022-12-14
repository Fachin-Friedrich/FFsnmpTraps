using System;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using csJson;
using System.Collections.Generic;
using SnmpSharpNet;

namespace FFsnmpTrapService
{
    public partial class Service : ServiceBase
    {
        private static void SetCulture()
        {
            Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfoByIetfLanguageTag("de");
        }

        void WriteLogSimple(string txt, EventLogEntryType eventtype = EventLogEntryType.Information)
        {
            elog.WriteEntry(message: txt, type: eventtype);
            logfile.WriteLine($"[{DateTime.Now}|{eventtype}] {txt}");
            logfile.Flush();
        }

        public Service()
        {
            InitializeComponent();
        }

        void WriteEvent(string hostname, SnmpV2Packet pkt, byte[] raw)
        {
            var output = new System.Text.StringBuilder();

            output.AppendLine("SNMP v2");
            output.AppendLine($"Agent address: {hostname}");
            output.AppendLine($"Community: {pkt.Community}");
            output.AppendLine($"Message count: {pkt.Pdu.VbList.Count}");
            output.AppendLine("---");
            foreach (var v in pkt.Pdu.VbList)
            {
                output.AppendLine($"{v.Oid} - {SnmpConstants.GetTypeName(v.Value.Type)} : {v.Value}");
            }

            string result = output.ToString();
            logfile.Write($"[{DateTime.Now}]\r\n{result}\r\n---\r\n");
            logfile.Flush();
            elog.WriteEntry(
                message: result,
                type: EventLogEntryType.Warning,
                eventID: pkt.Pdu.ErrorIndex % 0xFFFF,
                category: (short)pkt.Pdu.ErrorStatus,
                rawData: raw
            );
        }

        private static string GetHostName( IPEndPoint ep )
        {
            try
            {
                try
                {
                    string name = System.Net.Dns.GetHostEntry(ep.Address).HostName;
                    return $"{ep.Address} ({name})";
                }
                catch( Exception e )
                {
                    return ep.Address.ToString();
                }
            }
            catch( Exception e )
            {
                return "Unkown";
            }
        }

        void WriteEvent(string hostname, TrapPdu data, byte[] raw)
        {
            var output = new System.Text.StringBuilder();
            output.AppendLine($"SNMP v1");

            if (mib_records.ContainsKey(data.Specific))
            {
                var mib = mib_records[data.Specific];
                output.AppendLine(mib.Description);
                output.AppendLine($"Sensor {mib.TrapType}");
            }

            //output.AppendLine($"Generic: {data.Generic} - Specific: {data.Specific}");
            output.AppendLine($"Agent address: {hostname}");
            output.AppendLine($"Message count: {data.VbList.Count}");
            output.AppendLine("---");
            foreach (var v in data.VbList)
            {
                output.AppendLine($"{v.Oid} - {SnmpConstants.GetTypeName(v.Value.Type)} : {v.Value}");
            }

            string result = output.ToString();
            logfile.Write($"[{DateTime.Now}]\r\n{result}\r\n---\r\n");
            logfile.Flush();
            elog.WriteEntry(
                message: result,
                type: EventLogEntryType.Warning,
                eventID: data.Specific % 0xFFFF,
                category: (short)data.Generic,
                rawData: raw
            );
        }

        private StreamWriter logfile;
        private Thread main_thread;
        private UdpClient trap_listener;
        private EventLog elog;
        private Dictionary<int, MIBRecord> mib_records;
        private bool graceful_stop;
        private bool want_continue;

        void HandleTrap(byte[] raw, IPEndPoint ep)
        {
            SetCulture();
            WriteLogSimple("Trap message recieved");

            try
            {
                int version = SnmpPacket.GetProtocolVersion(raw, raw.Length);
                string hostname = GetHostName(ep);

                switch (version)
                {
                    case (int)SnmpVersion.Ver1:

                        var pkt1 = new SnmpV1TrapPacket();
                        pkt1.decode(raw, raw.Length);
                        WriteEvent(hostname, pkt1.TrapPdu, raw);
                        break;

                    case (int)SnmpVersion.Ver2:

                        var pkt2 = new SnmpV2Packet();
                        pkt2.decode(raw, raw.Length);
                        if (pkt2.Pdu.Type != PduType.V2Trap)
                        {
                            throw new Exception("Captured corrupted SNMP V2 Package");
                        }

                        WriteEvent(hostname, pkt2, raw);
                        break;

                    default:
                        throw new Exception($"Unsupported SNMP version: {version}");
                }
            }
            catch (Exception e)
            {
                WriteLogSimple(e.ToString(), EventLogEntryType.Error);
            }
        }

        private void NetworkLoop()
        {
            SetCulture();
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            string logname = "logs\\" + DateTime.Now.ToString("ddd_dd_MMM_yyyy_HH_mm_ss") + ".log";
            Directory.CreateDirectory("logs");
            logfile = new StreamWriter(logname, append: true);
            graceful_stop = true;
            want_continue = true;

            try
            {
                if( !EventLog.SourceExists("FFTraps"))
                {
                    EventLog.CreateEventSource("FFTraps", "Application");
                }
                elog = new EventLog();
                elog.Log = "Application";
                elog.Source = "FFTraps";
                WriteLogSimple("FFTraps started.");
            }
            catch( Exception e)
            {
                logfile.WriteLine($"[{DateTime.Now}|Fatal] {e}\r\n----------");
                logfile.Flush();
                want_continue = false;
                graceful_stop = false;
                Stop();
            }

            try
            {
                //Init mib records here
                var file = File.OpenRead("devicemapping.json");
                var buffer = new byte[file.Length];
                file.Read(buffer, 0, (int)file.Length);
                file.Close();

                string raw = System.Text.ASCIIEncoding.UTF8.GetString(buffer);
                var json = jsonRoot.Parse(raw);
                string man = MainboardInfo.Manufacturer;

                mib_records = null;
                var manufacturers = json["ByManufacturer"].Array;
                for (ulong i = 0; i < manufacturers.Elements; ++i)
                {
                    var obj = manufacturers[i].Object;
                    if (obj["Manufacturer"].String == man)
                    {
                        string filepath = obj["File"].String;
                        mib_records = MIBParserLite.Parse(filepath);
                        WriteLogSimple($"{filepath} loaded.");
                    }
                }

                if (mib_records == null)
                {
                    throw new Exception($"Failed to match MIB-File for device for manufacturer \"{man}\"");
                }

                trap_listener = new UdpClient(162);
                while (want_continue)
                {
                    var ep = new IPEndPoint(IPAddress.Any, 162);
                    buffer = trap_listener.Receive(ref ep);

                    if( buffer.Length > 0)
                    {
                        new Thread(() => HandleTrap(buffer, ep)).Start();
                    }
                    else
                    {
                        WriteLogSimple($"Zero length trap receieved from {ep.Address}");
                    }
                }
            }
            catch( Exception e)
            {
                if (want_continue)
                {
                    WriteLogSimple(e.ToString(), EventLogEntryType.Error);
                    graceful_stop = false;
                    Stop();
                }
            }

        }

        protected override void OnStart(string[] args)
        {
            main_thread = new Thread(NetworkLoop);
            main_thread.Start();
        }

        protected override void OnStop()
        {
            SetCulture();

            try
            {
                want_continue = false;
                if (graceful_stop)
                {
                    trap_listener.Close();
                    main_thread.Join();
                    WriteLogSimple("Service has stopped");
                }
                else
                {
                    WriteLogSimple("Service stopped abnormally", EventLogEntryType.Error);
                }
            }
            catch( Exception e)
            {
                WriteLogSimple(e.ToString(), EventLogEntryType.Error);
            }
        }

        protected override void OnShutdown()
        {
            OnStop();
            base.OnShutdown();
        }
    }
}
