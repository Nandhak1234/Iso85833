using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace nan
{
    public enum LengthType
    {
        Fixed,
        L,
        LL,
        LLL,
    }
    public class DataElement
    {
        public string Id { get; set; }
        public int PositionInTheMsg { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public LengthType FieldLength { get; set; }
        public LengthType FieldLengthRepresentation { get; set; }
    }
}
