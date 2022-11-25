using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;

namespace Experimental
{
    public struct MIBRecord
    {
        public readonly int Id;
        public readonly string Enterprise;
        public readonly string TrapType;
        public readonly string Description;
        public readonly string[] Variables;
        public readonly int Index;

        internal MIBRecord( string idstr, string entp, string tt, string vraw, string desc, int ndx )
        {
            Id = int.Parse(idstr);
            Enterprise = entp;
            TrapType = tt;
            Variables = vraw.Split(',');
            Description = desc;
            Index = ndx;
            for( int i = 0; i < Variables.Length; ++i)
            {
                Variables[i] = Variables[i].Trim();
            }
        }
    }
    
    public static class MIBParserLite
    {
        public enum Version
        {
            V1
        }

        private const string RecoredMarker = "::=";

        private static Dictionary<int,MIBRecord> Parse_V1( string fname)
        {
            var file = File.Open(
                fname, 
                FileMode.Open,
                FileAccess.Read, 
                FileShare.Write
            );

            var buffer = new byte[file.Length];
            file.Read(buffer, 0, (int)file.Length);
            file.Close();

            string raw = UTF8Encoding.UTF8.GetString(buffer);
            int section_end = raw.LastIndexOf(RecoredMarker);
            int section_begin = raw.LastIndexOf(RecoredMarker, section_end - 1);

            if( section_end == -1 || section_begin == -1)
            {
                //TODO handle no sections found
            }

            var result = new Dictionary<int, MIBRecord>();
            int ndx = 0;

            while (true)
            {
                int pos_lb = raw.IndexOf('\n', section_end) - 1;
                string idstr = raw.Substring(section_end, pos_lb - section_end);
                Match idmatch = Regex.Match(idstr, "[0-9]+$");

                if (!idmatch.Success) break;

                // Extract description
                int pos_desc0 = raw.IndexOf("DESCRIPTION", section_begin);
                int pos_desc1 = raw.IndexOf('\"', pos_desc0) + 1;
                int pos_desc2 = raw.IndexOf('\"', pos_desc1) + 1;
                string desc_raw = raw.Substring(pos_desc0, pos_desc2 - pos_desc0);
                Match desc_match = Regex.Match(desc_raw, "\".*\"");

                // Extract enterprise
                int ent_pos0 = raw.IndexOf("ENTERPRISE", section_begin);
                int ent_pos1 = raw.IndexOf(' ', ent_pos0) + 1;
                int ent_pos2 = raw.IndexOf('\n', ent_pos1);
                string enterprise = raw.Substring(ent_pos1, ent_pos2 - ent_pos1);

                // Extract trap-type
                string traptype = string.Empty;
                int tt_pos0 = raw.IndexOf("TRAP-TYPE", section_begin);
                if( tt_pos0 < section_end && tt_pos0 != -1 )
                {
                    int tt_pos1 = raw.LastIndexOf('\n', tt_pos0) + 1;
                    traptype = raw.Substring(tt_pos1, tt_pos0 - tt_pos1);
                }

                // Extract variables
                int var_pos0 = raw.IndexOf("VARIABLES", section_begin);
                string var_raw = string.Empty;
                if( var_pos0 < section_end && var_pos0 != -1)
                {
                    int var_pos1 = raw.IndexOf('{', var_pos0) + 1;
                    int var_pos2 = raw.IndexOf('}', var_pos1);
                    var_raw = raw.Substring(var_pos1, var_pos2 - var_pos1);
                }

                var record = new MIBRecord(idmatch.Value, enterprise, traptype, var_raw, desc_match.Value, ++ndx);
                result.Add(record.Id, record);

                section_end = section_begin;
                section_begin = raw.LastIndexOf(RecoredMarker, section_begin - 1);
            }

            return result;
        }

        public static Dictionary<int, MIBRecord> Parse(string filename) => Parse_V1(filename);

        public static Dictionary<int,MIBRecord> Parse( string filename, Version v )
        {
            switch( v)
            {
                case Version.V1: return Parse_V1(filename);
                default: throw new Exception($"Using MIB Parser Lite Version {v} is not supported");
            }
        }

    } // End of class

} // End of namespace
