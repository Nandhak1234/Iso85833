
using nan;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ISO
{
    internal class Helper
    {
        static int STAN = 0;
        internal static string TransmissionDateTime(string dateTimeFormat)
        {
            DateTime transDT = DateTime.Now;
            return transDT.ToString(dateTimeFormat);
        }

        internal static string FetchStan()
        {
            STAN = STAN + 1;

            return STAN.ToString();
        }

        internal static string BitArrayToHexString(BitArray bitArray)
        {
            int numBytes = (bitArray.Length + 7) / 8;
            byte[] bytes = new byte[numBytes];
            bitArray.CopyTo(bytes, 0);

            return BitConverter.ToString(bytes).Replace("-", "");
        }

        internal static string BitArrayToString(BitArray bitArray)
        {
            char[] bits = new char[bitArray.Length];
            for (int i = 0; i < bitArray.Length; i++)
            {
                //bitArray[i] = bitArray[i] ? '1' : '0';
            }

            return new string(bits);
        }

        internal static string BitArrayToHexadecimalString(BitArray bitArray)
        {
            int padding = 4 - (bitArray.Length % 4);

            if (padding != 4)
            {
                BitArray paddedBits = new BitArray(bitArray.Length + padding);
                for (int i = 0; i < bitArray.Length; i++)
                {
                    paddedBits[i] = bitArray[i];
                }
                bitArray = paddedBits;
            }

            int numBytes = bitArray.Length / 8;
            byte[] bytes = new byte[numBytes];
            bitArray.CopyTo(bytes, 0);

            return BitConverter.ToString(bytes).Replace("-", "");
        }

        internal static String PrepareVariableFieldData(DataElement de)
        {
            int length = de.Value.Length;
            string str = length.ToString();
            de.Value = str + de.Value;
            return de.Value;
        }


        internal static BitArray PrepareBitarrayForBitMap(List<DataElement> sortedDataElementsList)
        {
            DataElement last = sortedDataElementsList[sortedDataElementsList.Count - 1];
            BitArray bits = new BitArray(64);

            if (last.PositionInTheMsg > 64 && last.PositionInTheMsg <= 128)
            {
                bits = new BitArray(128);
            }
            else if (last.PositionInTheMsg > 128 && last.PositionInTheMsg <= 192)
            {
                bits = new BitArray(128);
            }
            return bits;
        }


        public static string PrepareVariableFieldDataWithLength(string data, int lengthDigits)
        {
            if (string.IsNullOrEmpty(data))
            {
                return "";
            }
            int dataLength = data.Length;
            if (dataLength > Math.Pow(10, lengthDigits) - 1)
            {
                throw new ArgumentException("Data length exceeds the maximum allowed length.");
            }
            string lengthPrefix = dataLength.ToString().PadLeft(lengthDigits, '0');
            string result = lengthPrefix + data;

            return result;
        }


    }
}

