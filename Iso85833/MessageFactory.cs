using nan;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using ISO;
using System.Text;
using System.Threading;
using System.Web;
using ISO8583;
using static Programs;


namespace ISO
{
    public enum RequiredMsg
    {
        None = 0,
        SignOn,
        SignOff,
        BalanceInquiry,
        CashWithdrawal,
        Emv,
        arqc
    }

    internal class MessageFactory
    {
        internal static string ConstructMessage(RequiredMsg reqMsg)
        {
            string message = string.Empty;
            switch (reqMsg)
            {
                case RequiredMsg.SignOn:
                    message = SignOn();
                    break;
                case RequiredMsg.SignOff:
                    message = SignOff();
                    break;
                case RequiredMsg.BalanceInquiry:
                    string track2Data = "1234567890123456=22021015432112345678";
                    string pin = "1234";
                    string key = "ED2307743BAFC53FA0315C89116BCABF";
                    message = BalanceInquiry(track2Data, pin, key);
                    break;
                case RequiredMsg.CashWithdrawal:
                    string track2Data1 = "1234567890123456=22021015432112345678";
                    string pin1 = "1234";
                    string key1 = "ED2307743BAFC53FA0315C89116BCABF";
                    message = CashWithdrawal(track2Data1, pin1, key1);
                    break;
                case RequiredMsg.Emv:
                    EmvTags.Emv();
                    break;
                case RequiredMsg.arqc:
                    Arqc_Data.ARQC();
                    break;
                default:
                    Console.Write("Option invalid.");
                    break;
            }

            return message;
        }

        private static string BalanceInquiry(string track2Data, string pin, string key)
        {
            List<DataElement> requiredDataelements = new List<DataElement>();
            string pinBlock = PinTranslator.CalculatePinBlock(pin);
            string panBlock = PinTranslator.CalculatePanBlock(track2Data);
            string pinPanBlock = PinTranslator.CalculatePinPanBlock(pinBlock, panBlock);
            byte[] dataBytes = PinTranslator.HexStringToByteArray(pinPanBlock);
            byte[] keyBytes = PinTranslator.HexStringToByteArray(key);
            byte[] encryptedData = PinTranslator.Encrypt3DES(dataBytes, keyBytes);

            // Convert the encrypted byte array to a hexadecimal string
            string encryptedHex = PinTranslator.ByteArrayToHexString(encryptedData);

            // Print the encrypted result
            Console.WriteLine("The Pinblock is:" + pinBlock);
            Console.WriteLine("The Panblock is:" + panBlock);
            Console.WriteLine("The Non-Encrypted PinPan Block is:" + pinPanBlock);
            Console.WriteLine("Encrypted Data: " + encryptedHex + "\n");

            requiredDataelements.Add(new DataElement { Id = "Header", PositionInTheMsg = -1, Name = "Header", Value = "ISO004000000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-001", PositionInTheMsg = 1, Name = "MTI", Value = "1200", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-002", PositionInTheMsg = 2, Name = "PAN", Value = "5351290102107506", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-003", PositionInTheMsg = 3, Name = "Processing Code", Value = "310000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-004", PositionInTheMsg = 4, Name = "Transaction Amount", Value = "000000100000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-005", PositionInTheMsg = 5, Name = "Reconciliation Amount", Value = "000000100000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-007", PositionInTheMsg = 7, Name = "Transmission Date Time", Value = Helper.TransmissionDateTime("MMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-009", PositionInTheMsg = 9, Name = "Reconciliation Conversion Rate", Value = "00001234", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-011", PositionInTheMsg = 11, Name = "System Trace Audit Number", Value = Helper.FetchStan(), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-012", PositionInTheMsg = 12, Name = "Local Transaction Date & Time", Value = Helper.TransmissionDateTime("yyMMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-016", PositionInTheMsg = 16, Name = "Conversion Date", Value = "0916", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-017", PositionInTheMsg = 17, Name = "Capture Date", Value = "0916", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-022", PositionInTheMsg = 22, Name = "Point of Service Data Code", Value = "100101100010", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-023", PositionInTheMsg = 23, Name = "Card Sequence Number", Value = "001", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-026", PositionInTheMsg = 26, Name = "Card Acceptor Business Code", Value = "6010", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-030", PositionInTheMsg = 30, Name = "Original Amounts", Value = "0000000100000001000000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-032", PositionInTheMsg = 32, Name = "Acquirer Institution Identification Code", Value = "98765432109", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-035", PositionInTheMsg = 35, Name = "Track 2 Data", Value = "1234567890123456=22021015432112345678", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-037", PositionInTheMsg = 37, Name = "Retrieval Reference Number", Value = "ABC123XYZ456", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-038", PositionInTheMsg = 38, Name = "Approval Code", Value = "ABC123", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-039", PositionInTheMsg = 39, Name = "Action Code", Value = "000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-041", PositionInTheMsg = 41, Name = "Card Acceptor Terminal Identification", Value = "A1#9B$5C&7*1D3EFGH4I5J6K", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-042", PositionInTheMsg = 42, Name = "Card Acceptor Identification Code", Value = "A1#9B$5C&7*1D3EFGH4I5J6", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-043", PositionInTheMsg = 43, Name = "Card Acceptor Name/Location", Value = "Terminal Owner\\Terminal Street\\Terminal City\\12345\\Region\\USA", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-048", PositionInTheMsg = 48, Name = "keerthana", Value = "1234$^&ZXDYTFFG", FieldLengthRepresentation = LengthType.LLL });
            requiredDataelements.Add(new DataElement { Id = "DE-049", PositionInTheMsg = 49, Name = "Transaction Currency Code", Value = "784", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-050", PositionInTheMsg = 50, Name = "Reconciliation Currency Code", Value = "123", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-052", PositionInTheMsg = 52, Name = "Personal Identification Number (PIN) Data", Value = encryptedHex, FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-053", PositionInTheMsg = 53, Name = "Security Related Control Information", Value = "0101101010", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-054", PositionInTheMsg = 54, Name = "Additional Amounts", Value = "1250ABC&@123", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-055", PositionInTheMsg = 55, Name = "Integrated Circuit Card System Related Data", Value = "1010101010100010111101", FieldLengthRepresentation = LengthType.LL });
            return TransactionMessage(requiredDataelements);


        }

        private static string CashWithdrawal(string track2Data, string pin, string key)
        {
            List<DataElement> requiredDataelements = new List<DataElement>();
            string pinBlock = PinTranslator.CalculatePinBlock(pin);
            string panBlock = PinTranslator.CalculatePanBlock(track2Data);
            string pinPanBlock = PinTranslator.CalculatePinPanBlock(pinBlock, panBlock);
            byte[] dataBytes = PinTranslator.HexStringToByteArray(pinPanBlock);
            byte[] keyBytes = PinTranslator.HexStringToByteArray(key);
            byte[] encryptedData = PinTranslator.Encrypt3DES(dataBytes, keyBytes);

            // Convert the encrypted byte array to a hexadecimal string
            string encryptedHex = PinTranslator.ByteArrayToHexString(encryptedData);

            // Print the encrypted result
            Console.WriteLine("The Pinblock is:" + pinBlock);
            Console.WriteLine("The Panblock is:" + panBlock);
            Console.WriteLine("The Non-Encrypted PinPan Block is:" + pinPanBlock);
            Console.WriteLine("Encrypted Data: " + encryptedHex + "\n");

            requiredDataelements.Add(new DataElement { Id = "Header", PositionInTheMsg = -1, Name = "Header", Value = "ISO004000000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-001", PositionInTheMsg = 1, Name = "MTI", Value = "1200", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-002", PositionInTheMsg = 2, Name = "PAN", Value = "5351290102107506", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-003", PositionInTheMsg = 3, Name = "Processing Code", Value = "010000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-004", PositionInTheMsg = 4, Name = "Transaction Amount", Value = "000000100000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-005", PositionInTheMsg = 5, Name = "Reconciliation Amount", Value = "000000100000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-007", PositionInTheMsg = 7, Name = "Transmission Date Time", Value = Helper.TransmissionDateTime("MMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-009", PositionInTheMsg = 9, Name = "Reconciliation Conversion Rate", Value = "00001234", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-011", PositionInTheMsg = 11, Name = "System Trace Audit Number", Value = Helper.FetchStan(), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-012", PositionInTheMsg = 12, Name = "Local Transaction Date & Time", Value = Helper.TransmissionDateTime("yyMMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-016", PositionInTheMsg = 16, Name = "Conversion Date", Value = "0916", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-017", PositionInTheMsg = 17, Name = "Capture Date", Value = "0916", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-022", PositionInTheMsg = 22, Name = "Point of Service Data Code", Value = "100101100010", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-023", PositionInTheMsg = 23, Name = "Card Sequence Number", Value = "001", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-025", PositionInTheMsg = 25, Name = "Message Reason Code", Value = "0123", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-026", PositionInTheMsg = 26, Name = "Card Acceptor Business Code", Value = "6010", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-030", PositionInTheMsg = 30, Name = "Original Amounts", Value = "0000000100000001000000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-032", PositionInTheMsg = 32, Name = "Acquirer Institution Identification Code", Value = "98765432109", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-035", PositionInTheMsg = 35, Name = "Track 2 Data", Value = "1234567890123456=22021015432112345678", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-037", PositionInTheMsg = 37, Name = "Retrieval Reference Number", Value = "ABC123XYZ456", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-038", PositionInTheMsg = 38, Name = "Approval Code", Value = "ABC123", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-039", PositionInTheMsg = 39, Name = "Action Code", Value = "000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-041", PositionInTheMsg = 41, Name = "Card Acceptor Terminal Identification", Value = "A1#9B$5C&7*1D3EFGH4I5J6K", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-042", PositionInTheMsg = 42, Name = "Card Acceptor Identification Code", Value = "A1#9B$5C&7*1D3EFGH4I5J6", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-043", PositionInTheMsg = 43, Name = "Card Acceptor Name/Location", Value = "Terminal Owner\\Terminal Street\\Terminal City\\12345\\Region\\USA", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-046", PositionInTheMsg = 46, Name = "Fee Amounts", Value = "701USD000100.50234.56001USD", FieldLengthRepresentation = LengthType.LLL });
            requiredDataelements.Add(new DataElement { Id = "DE-049", PositionInTheMsg = 49, Name = "Transaction Currency Code", Value = "784", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-050", PositionInTheMsg = 50, Name = "Reconciliation Currency Code", Value = "123", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-052", PositionInTheMsg = 52, Name = "Personal Identification Number (PIN) Data", Value = encryptedHex, FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-053", PositionInTheMsg = 53, Name = "Security Related Control Information", Value = "0101101010", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-054", PositionInTheMsg = 54, Name = "Additional Amounts", Value = "1250ABC&@123", FieldLengthRepresentation = LengthType.LL });
            requiredDataelements.Add(new DataElement { Id = "DE-055", PositionInTheMsg = 55, Name = "Integrated Circuit Card System Related Data", Value = "1010101010100010111101", FieldLengthRepresentation = LengthType.LL });
            return TransactionMessage(requiredDataelements);
        }

        private static string SignOn()
        {
            List<DataElement> requiredDataelements = new List<DataElement>();

            requiredDataelements.Add(new DataElement { Id = "Header", PositionInTheMsg = -1, Name = "Header", Value = "ISO004000000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-001", PositionInTheMsg = 1, Name = "MTI", Value = "1804", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-007", PositionInTheMsg = 7, Name = "Transmission Date Time", Value = Helper.TransmissionDateTime("MMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-011", PositionInTheMsg = 11, Name = "System Trace Audit Number", Value = Helper.FetchStan(), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-012", PositionInTheMsg = 12, Name = "Local Transaction Date Time", Value = Helper.TransmissionDateTime("yyMMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-024", PositionInTheMsg = 24, Name = "Function Code", Value = "801", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-028", PositionInTheMsg = 28, Name = "Reconciliation Date", Value = Helper.TransmissionDateTime("yyMMdd"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-093", PositionInTheMsg = 93, Name = "Transaction Destination Institution ID", Value = "00000000000" });
            requiredDataelements.Add(new DataElement { Id = "DE-094", PositionInTheMsg = 94, Name = "Transaction Originator Institution ID", Value = "00000000000" });
            return TransactionMessage(requiredDataelements);
        }

        private static string SignOff()
        {
            List<DataElement> requiredDataelements = new List<DataElement>();

            requiredDataelements.Add(new DataElement { Id = "Header", PositionInTheMsg = -1, Name = "Header", Value = "ISO004000000", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-001", PositionInTheMsg = 1, Name = "MTI", Value = "1804", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-007", PositionInTheMsg = 7, Name = "Transmission Date Time", Value = Helper.TransmissionDateTime("MMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-011", PositionInTheMsg = 11, Name = "System Trace Audit Number", Value = Helper.FetchStan(), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-012", PositionInTheMsg = 12, Name = "Local Transaction Date Time", Value = Helper.TransmissionDateTime("yyMMddhhmmss"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-024", PositionInTheMsg = 24, Name = "Function Code", Value = "802", FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-028", PositionInTheMsg = 28, Name = "Reconciliation Date", Value = Helper.TransmissionDateTime("yyMMdd"), FieldLengthRepresentation = LengthType.Fixed });
            requiredDataelements.Add(new DataElement { Id = "DE-093", PositionInTheMsg = 93, Name = "Transaction Destination Institution ID", Value = "00000000000" });
            requiredDataelements.Add(new DataElement { Id = "DE-094", PositionInTheMsg = 94, Name = "Transaction Originator Institution ID", Value = "00000000000" });
            return TransactionMessage(requiredDataelements);
        }

        private static string TransactionMessage(List<DataElement> dataElements)
        {
            List<DataElement> sortedDataElementsList = dataElements.OrderBy(x => x.PositionInTheMsg).ToList();

            StringBuilder Msg = new StringBuilder();

            foreach (DataElement de in sortedDataElementsList)
            {
                if (de.FieldLengthRepresentation == LengthType.Fixed)
                {
                    Msg.Append(de.Value);
                }
                else
                {
                    Msg.Append(Helper.PrepareVariableFieldData(de));
                }



                if (de.PositionInTheMsg == 1)
                {
                    Msg.Append(PrepareBitMap(sortedDataElementsList, Helper.PrepareBitarrayForBitMap(sortedDataElementsList)));
                }
            }


            return Msg.ToString();
        }


        private static string PrepareBitMap(List<DataElement> sortedDataElementsList, BitArray bits)
        {
            foreach (DataElement de in sortedDataElementsList)
            {
                if (de.PositionInTheMsg >= 1)
                {
                    int PositionOfBit = de.PositionInTheMsg - 1;
                    bits.Set(PositionOfBit, true);
                }
            }
            return Helper.BitArrayToHexadecimalString(bits);
        }
    }

}
