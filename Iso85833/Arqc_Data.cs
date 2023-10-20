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
        public static void ARQC(string ARQCdata)
        {
            string mdk = "7B3D21A4F9C2E0563A9D5B1F8E4C7B9D";
            string dki = "01";
            string track2data = ";5351290102107506=21112011557206710000?";
            string cardnum = Cardnum(track2data);
            string seqno = dki;
            string concatenate = cardnum + seqno;
            concatenate = concatenate.Substring(2);
            string UDK_A = Encrypt3DES(concatenate, mdk);
            string xorvalue = XOR(concatenate, "ffffffffffffffff");
            string UDK_B = Encrypt3DES(xorvalue, mdk);
            string Final_UDK = UDK_A + UDK_B;
            string sessionkey = Final_UDK;
            Console.WriteLine("The sessionkey is " + sessionkey);
            Console.WriteLine("The Generated ARQC is " + Operation(ARQCdata, sessionkey));
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
            string R1 = "0001F00000000000";
            string R2 = "00010F0000000000";
            string SKA = Encrypt3DES(R1, Final_UDk);
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


        private static string Operation(string ARQCdata, string sessionkey)
        {
            List<string> chunks = new List<string>();
            ARQCdata = ARQCdata + "A00003240000" + "000000" + "80";
            int len = ARQCdata.Length;
            int rem = len % 8;
            bool rep = true;
            while (rep)
            {
                if (rem != 0)
                {
                    ARQCdata = ARQCdata + "0";
                    len = ARQCdata.Length;
                    rem = len % 8;
                }
                if (rem == 0)
                {
                    rep = false;
                }
            }
            Console.WriteLine("The CDOL data is " + ARQCdata);
            string session1 = sessionkey.Substring(0, 16);
            string session2 = sessionkey.Substring(16);
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
    }
}
