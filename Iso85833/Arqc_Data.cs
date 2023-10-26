using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System.Security.Cryptography;

namespace ISO8583
{
    class Arqc_Data
    {
        public static void ARQC()
        {
            string tlvString = "";

            List<TLV> arqclist = new List<TLV>
            {
                new TLV { Id = "9F02", Name = "Amount Authorized",Value="000000100000" },
                new TLV { Id = "9F03", Name = "Amount, Other ", Value = "000000000000" },
                new TLV { Id = "9F1A", Name = "Terminal Country Code ", Value = "0682" },
                new TLV { Id = "95", Name = "Terminal Verification Result ", Value = "0000000000" },
                new TLV { Id = "5F2A", Name = "Transaction Currency Code ", Value = "0682" },
                new TLV { Id = "9A", Name = "Transaction Date", Value = "231023" },
                new TLV { Id = "9C", Name = "Transaction Type", Value = "31" },
                //Keeps Changing 
                new TLV { Id = "9F37", Name = "Unpredictable Number", Value = "01613B75" },
                new TLV { Id = "82", Name = "Application Interchange Profile", Value = "3800" },
                new TLV { Id = "9F36", Name = "Application Transaction Counter (ATC)", Value = "000F" },
            
        };

           


            string mdk = "6E46FE409DF704BCA75E7FF270B65E73";
            string dki = "01";
            string track2data = ";4226810000000010=21112011557206710000?";
            string cardnum = Cardnum(track2data);
            string seqno = dki;
            string concatenate = cardnum + seqno;
            concatenate = concatenate.Substring(2);
            string UDK_A = Encrypt3DES(concatenate, mdk);
            //Console.WriteLine(UDK_A);
            string xorvalue = XOR(concatenate, "ffffffffffffffff");
            string UDK_B = Encrypt3DES(xorvalue, mdk);
            //Console.WriteLine(UDK_B);
            string Final_UDK = UDK_A + UDK_B;
            //Console.WriteLine(Final_UDK);
            string sessionkey = Session_Key(Final_UDK);
            Console.WriteLine("The sessionkey : " + sessionkey);
            foreach (TLV tlv in arqclist)
            {
                tlvString += $"{tlv.Value}";
            }

            if (!string.IsNullOrEmpty(tlvString))
            {
                tlvString = tlvString.TrimEnd(',');
            }

            // Convert the tlvString into an array by splitting it on commas
            string[] tlvArray = tlvString.Split(',');

            // Output the tlvArray
            foreach (string tlvItem in tlvArray)
            {
                Console.WriteLine("CDOL Data before padding : "+tlvItem);
            }

            Console.WriteLine("The Generated ARQC : " + Operation(tlvArray, sessionkey));
            Console.ReadKey();
        }

        private static string Cardnum(string track2data)
        {
            string[] parts = track2data.Split('=');
            string card = parts[0];
            card = card.Substring(1);
            return card;
        }
        private static string Encrypt3DES(string datastr, string keystr)
        {

            using (TripleDESCryptoServiceProvider desProvider = new TripleDESCryptoServiceProvider())
            {
                int byteCount = datastr.Length / 2;
                byte[] data = new byte[byteCount];
                for (int i = 0; i < byteCount; i++)
                {
                    data[i] = Convert.ToByte(datastr.Substring(i * 2, 2), 16);
                }
                int byteCount1 = keystr.Length / 2;
                byte[] key = new byte[byteCount1];
                for (int i = 0; i < byteCount1; i++)
                {
                    key[i] = Convert.ToByte(keystr.Substring(i * 2, 2), 16);
                }

                desProvider.Mode = CipherMode.ECB;
                desProvider.Padding = PaddingMode.None;
                desProvider.Key = key;
                ICryptoTransform encryptor = desProvider.CreateEncryptor();
                byte[] bytes = encryptor.TransformFinalBlock(data, 0, data.Length);
                string hex = string.Concat(bytes.Select(b => b.ToString("X2")));
                return hex;
            }
        }

        private static string XOR(string hexString1, string hexString2)
        {
            byte[] bytes1 = Enumerable.Range(0, hexString1.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hexString1.Substring(x, 2), 16))
                .ToArray();

            byte[] bytes2 = Enumerable.Range(0, hexString2.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hexString2.Substring(x, 2), 16))
                .ToArray();
            byte[] resultBytes = new byte[bytes1.Length];

            for (int i = 0; i < bytes1.Length; i++)
            {
                resultBytes[i] = (byte)(bytes1[i] ^ bytes2[i]);
            }

            string resultHexString = BitConverter.ToString(resultBytes).Replace("-", "").ToLower();
            return resultHexString;
        }
        private static string Session_Key(string Final_UDk)
        {
            string R1 = "000FF00000000000";
            string R2 = "000F0F0000000000";
            string SKA = Encrypt3DES(R1, Final_UDk);
            //Console.WriteLine(SKA);
            string SKB = Encrypt3DES(R2, Final_UDk);
            string Sessionkey = SKA + SKB;
            return Sessionkey;
        }
        private static string DESEncrypt(string data, string key)
        {
            byte[] dataBytes = Hex.Decode(data);
            byte[] keyBytes = Hex.Decode(key);
            IBlockCipher desEngine = new DesEngine();
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(desEngine));
            var keyParam = new KeyParameter(keyBytes);
            cipher.Init(true, keyParam);
            byte[] output = new byte[cipher.GetOutputSize(dataBytes.Length)];
            int length = cipher.ProcessBytes(dataBytes, output, 0);
            cipher.DoFinal(output, length);
            string encryptedResult = Hex.ToHexString(output).ToUpper();
            return encryptedResult;

        }
        private static string DESDecrypt(string encryptedData, string key)
        {
            byte[] dataBytes = Hex.Decode(encryptedData);
            byte[] keyBytes = Hex.Decode(key);

            IBlockCipher desEngine = new DesEngine();
            var cipher = new BufferedBlockCipher(new CbcBlockCipher(desEngine));
            var keyParam = new KeyParameter(keyBytes);

            cipher.Init(false, keyParam);

            byte[] output = new byte[cipher.GetOutputSize(dataBytes.Length)];
            int length = cipher.ProcessBytes(dataBytes, output, 0);

            cipher.DoFinal(output, length);

            string decryptedResult = Hex.ToHexString(output).ToUpper();
            return decryptedResult.Substring(0, 16);
        }


        private static string Operation(string[] tlvArray, string sessionkey)
        {
            List<string> chunks = new List<string>();
            // Convert tlvArray to a single string and append it to ARQCdata
            string ARQCdata = string.Join("", tlvArray) + "011203A0880000";
            //Console.WriteLine(ARQCdata);
            int len = ARQCdata.Length;
            //Console.WriteLine(len);
            int rem = len % 8;
            //Console.WriteLine(rem);
            bool rep = true;
           
            while (rep)
            {
                if (rem == 0)
                {
                  ARQCdata= ARQCdata + "80" + "00000000000000";
                    // Console.WriteLine("ARQCdata1 :"+ARQCdata);
                    rep = false;
                }
                if (rem != 0)
                {
                    ARQCdata = ARQCdata + "0";
                    //Console.WriteLine("ARQCdata2: "+ARQCdata);
                    len = ARQCdata.Length;
                    rem = len % 8;
                }
                if (rem == 0)
                {
                    rep = false;
                }
            }
            Console.WriteLine("CDOL Data after padding : " + ARQCdata);
            string session1 = sessionkey.Substring(0, 16);
            string session2 = sessionkey.Substring(16);

            for (int i = 0; i < ARQCdata.Length; i += 16)
            {
                string chunk = ARQCdata.Substring(i, Math.Min(16, ARQCdata.Length - i));
                chunks.Add(chunk);
            }
            string DE = DESEncrypt(chunks[0], session1).Substring(0, 16);
            int a = 1;
            int count = CountOccurrences(ARQCdata);
            for (int i = 0; i < count - 1; i++)
            {
                string XO = XOR(DE, chunks[a]);
                a = a + 1;
                for (int j = 0; j < count - 1; j++)
                {
                    DE = DESEncrypt(XO, session1).Substring(0, 16);

                }
            }

            string DD = DESDecrypt(DE, session2).Substring(0, 16);
            string Arqc = DESEncrypt(DD, session1).Substring(0, 16);
            string Desdata = DESEncrypt(ARQCdata, sessionkey);
            
            for (int i = 0; i < Desdata.Length; i += 16)
            {
                string chunk = Desdata.Substring(i, Math.Min(16, Desdata.Length - i));
                chunks.Add(chunk);
            }
            int lenn = chunks.Count;
            string str = DESDecrypt(chunks[lenn - 2], session2);
            string str1 = DESEncrypt(str, session1);
            return str1.Substring(0, 16);
        }
        public static int CountOccurrences(string data)
        {
            int len = data.Length;
            int count = len / 16;
            return count;
        }

    }
 }

