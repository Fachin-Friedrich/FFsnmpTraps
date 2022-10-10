using System;
using System.Collections.Generic;
using System.Threading;
using SnmpSharpNet;

namespace Experimental
{
    static class StringExtension
    {
        public static void Log( this string txt)
        {
            Console.WriteLine($"[{DateTime.Now}] {txt}");
        }

        public static void Log(this string txt, ConsoleColor col)
        {
            var c0 = Console.ForegroundColor;
            Console.ForegroundColor = col;
            Log(txt);
            Console.ForegroundColor = c0;
        }
    }
    
    class Program
    {        
        
        static void HandleV1Trap( byte[] raw)
        {
            var output = new System.Text.StringBuilder();
            var pkt = new SnmpV1TrapPacket();
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
            output.AppendLine($"Community: {pkt.Community}");
            output.AppendLine($"Message count: {pkt.Pdu.VbList.Count}");
            output.AppendLine("---");
            foreach( var v in pkt.Pdu.VbList)
            {
                output.AppendLine($"{v.Oid} - {SnmpConstants.GetTypeName(v.Value.Type)} : {v.Value}");
            }
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
                e.ToString().Log(ConsoleColor.DarkRed);
            }
        }
        
        static void Main(string[] args)
        {
            var socket = new System.Net.Sockets.UdpClient(162);

            while (true)
            {
                try
                {
                    var ep = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 162);
                    var buffer = socket.Receive(ref ep);
                    if( buffer.Length > 0)
                    {
                        new Thread(() => HandleTrap(buffer));
                    }
                    else
                    {
                        "Zero length Trap received".Log(ConsoleColor.Gray);
                    }

                }
                catch( Exception e )
                {
                    e.ToString().Log(ConsoleColor.Red);
                }

            }
        }

    } // End of class

} // End of namespace
