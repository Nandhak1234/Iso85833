using System;
using System.CodeDom;
using System.Collections.Generic;
using System.IO;
using System.Linq;

public enum TagLengthType
{
    Fixed,
    Variable,
    Min_Max,
    OrNum,
}
class TLV
{
    public string Name { get; set; }
    public string Id { get; set; }
    public TagLengthType TagLengthRep { get; set; }
    public int Length { get; set; }
    public int minLen { get; set; }
    public int maxLen { get; set; }
    public bool orLength { get; set; }
    public string Value { get; set; }
}
class EmvTags
{
    public static void Emv()
    { 
       string filePath = "emv-tags.txt";
        try
        {
            string emvData = File.ReadAllText(filePath);
          // string emvData = "9F060A12345678901234567890";
            List<TLV> emvTags = new List<TLV>
            {
                //Already having
                new TLV { Id = "9F06", Name = "Application Identifier (AID)",minLen=5,maxLen=16,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "5F34", Name = "Application Primary Account Number (PAN) Sequence Number" ,Length=1,TagLengthRep=TagLengthType.Fixed},
                new TLV { Id = "9F27", Name = "Cryptogram Information Data",Length=1,TagLengthRep= TagLengthType.Fixed},
                new TLV { Id = "9F26", Name = "Application Cryptogram" ,Length=8,TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F10", Name = "Issuer Application Data",minLen=0,maxLen=32,TagLengthRep= TagLengthType.Min_Max },
                new TLV { Id = "9F36", Name = "Application Transaction Counter (ATC)",Length=2 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F02", Name = "Amount, Authorized (Numeric)",Length=6, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F03", Name = "Amount, Other (Numeric)",Length=6 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F1A", Name = "Terminal Country Code" , Length = 2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "5F2A", Name = "Transaction Currency Code",Length = 2 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F37", Name = "Unpredictable Number",Length = 4 ,TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F33", Name = "Terminal Capabilities",Length = 3 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F1E", Name = "Interface Device (IFD) Serial Number",Length = 8 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "57",   Name = "Track 2 Data",minLen=0,maxLen=19,TagLengthRep=TagLengthType.Min_Max },
                new TLV { Id = "5A",   Name = "Application PAN",minLen=0,maxLen=10 ,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "82",   Name = "Application Interchange Profile",Length=2 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "8C",   Name = "Card Risk Management Data",minLen=0,maxLen=252,TagLengthRep= TagLengthType.Min_Max },
                new TLV { Id = "95",   Name = "Terminal Verification Results (TVR)" ,Length=5, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9A",   Name = "Transaction Date",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9C",   Name = "Transaction Type",Length=1 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9B",   Name = "Transaction Status Information",Length=2, TagLengthRep = TagLengthType.Fixed },
                new TLV { Id = "50",   Name = "Application Label",minLen=1,maxLen=16,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "5F57", Name = "Account Type",Length=1 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F01", Name = "Acquirer Identifier",Length=6 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F40", Name = "Additional Terminal Capabilities",Length=6 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "81",   Name = "Amount, Authorised (Binary)",Length=4 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F02", Name = "Amount, Authorised (Numeric)",Length=6 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "4F",   Name = "Application Dedicated File(ADF) Name",minLen=5,maxLen=16,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "50",   Name = "Application Label",minLen=1,maxLen=17,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "9F12", Name = "Application Preferred Name",minLen=1,maxLen=16,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "9F0A", Name = "Application Selection Registered Proprietary Data (ASRPD)", TagLengthRep = TagLengthType.Variable},//var
                new TLV { Id = "61",   Name = "Application Template",minLen=0,maxLen=252, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "9F07", Name = "Application Usage Control",Length=2 ,TagLengthRep=TagLengthType.Fixed},
                new TLV { Id = "9F08", Name = "Application Version Number",Length=2 ,TagLengthRep=TagLengthType.Fixed},
                new TLV { Id = "9F09", Name = "Application Version Number",Length=2 ,TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "89",   Name = "Authorisation Code",Length=6 ,TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "90",   Name = "Biometric Solution ID",TagLengthRep= TagLengthType.Variable},//VAR
                new TLV { Id = "82",   Name ="Biometric Subtype",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F30", Name ="Biometric Terminal Capabilities",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "BF4C", Name = "Biometric Try Counters Template", TagLengthRep = TagLengthType.Variable},//VAR
                new TLV { Id = "81",   Name = "Biometric Type",TagLengthRep=TagLengthType.Variable},//VAR
                new TLV { Id = "9F0B", Name = "Cardholder Name Extended",minLen=27,maxLen=45,TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "8E",   Name = "Cardholder Verification Method (CVM) List",minLen=10,maxLen=252,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "9F34", Name ="Cardholder Verification Method (CVM) Results",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "8F",   Name ="Certification Authority Public Key Index",Length=1 ,TagLengthRep= TagLengthType.Fixed},
                new TLV { Id = "9F22", Name ="Certification Authority Public Key Index",Length=1 ,TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "73",   Name = "Directory Discretionary Template",minLen=0,maxLen=252, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "9F49", Name = "Dynamic Data Authentication Data Object List (DDOL)",minLen=0,maxLen=252, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "DF51", Name = "Enciphered Biometric Data",TagLengthRep= TagLengthType.Variable},//VAR
              //new TLV { Id = "DF50", Name = "Enciphered Biometric Key Seed",Length=0},-->Ambiguity:Reason:unable to understand the length parameter(page.no:145)
                new TLV { Id = "DF50", Name ="Facial Try Counter",Length=1,TagLengthRep= TagLengthType.Fixed},
                new TLV { Id = "BF0C", Name = "File Control Information (FCI) Issuer Discretionary Data",minLen=0,maxLen=252, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "DF51", Name ="Finger Try Counter",Length=1 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F2E", Name = "Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent",minLen=1,maxLen=3,TagLengthRep= TagLengthType.OrNum},// OR
                new TLV { Id = "9F2F", Name ="Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder",Length=42,TagLengthRep= TagLengthType.Fixed},
                new TLV { Id = "9F46", Name ="Integrated Circuit Card (ICC) Public Key Certificate",Length=17 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F47", Name = "Integrated Circuit Card (ICC) Public Key Exponent",minLen=1,maxLen=3,TagLengthRep= TagLengthType.OrNum},//OR
                new TLV { Id = "9F48", Name ="Integrated Circuit Card (ICC) Public Key Remainder",Length=42,TagLengthRep= TagLengthType.Fixed },
                new TLV { Id = "91",   Name = "Issuer Authentication Data",minLen=8,maxLen=16,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "9F11", Name ="Issuer Code Table Index",Length=1,TagLengthRep= TagLengthType.Fixed },
                new TLV { Id = "5F28", Name ="Issuer Country Code",Length=2 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "5F55", Name ="Issuer Country Code (alpha2 format)",Length=2 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "5F56", Name ="Issuer Country Code (alpha3 format)",Length=3 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "42",   Name ="Issuer Identification Number (IIN)",Length=3 , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F0C", Name ="Issuer Identification Number Extended (IINE)",minLen=3,maxLen=4 ,TagLengthRep=TagLengthType.OrNum},//OR
                new TLV { Id = "5F2D", Name = "Language Preference",minLen=2,maxLen=8,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "9F25", Name ="Last 4 Digits of PAN",Length=2 ,TagLengthRep=TagLengthType.Fixed},
                new TLV { Id = "9F13", Name ="Last Online Application Transaction Counter (ATC) Register",Length=2,TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F4D", Name ="Log Entry ",Length=2,TagLengthRep= TagLengthType.Fixed },
                new TLV { Id = "9F4F", Name = "Log Format ",TagLengthRep= TagLengthType.Variable},// VAR
                new TLV { Id = "9F14", Name ="Lower  Consecutive  Offline Limit",Length=2 ,TagLengthRep= TagLengthType.Fixed},
                new TLV { Id = "DF52", Name ="MAC of Enciphered Biometric Data",Length=8 ,TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "BF4B", Name = "Online BIT Group Template ",TagLengthRep=TagLengthType.Variable},//->VAR
                new TLV { Id = "DF53", Name ="Palm Try Counter ",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F24", Name ="Payment Account Reference (PAR) ",Length=29, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F17", Name ="Personal Identification Number (PIN) Try Counter ",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F39", Name ="Point-of-Service (POS) Entry Mode",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F38", Name = "Processing Options Data Object List (PDOL)",TagLengthRep= TagLengthType.Variable},//->Edit for VAR
                new TLV { Id = "70",   Name = "READ RECORD Response Message Template",minLen=0,maxLen=252,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "80",   Name = "Response Message Template Format 1",TagLengthRep=TagLengthType.Variable},//-VAR
                new TLV { Id = "77",   Name = "Response Message Template Format 2",TagLengthRep=TagLengthType.Variable},//-VAR
                new TLV { Id = "5F30", Name ="Service Code ",Length=2 ,TagLengthRep= TagLengthType.Fixed},
                new TLV { Id = "88",   Name ="Short File Identifier (SFI) ",Length=1,TagLengthRep= TagLengthType.Fixed },
                new TLV { Id = "9F33", Name ="Terminal Capabilities",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F33", Name ="Terminal Capabilities",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F1A", Name ="Terminal Country Code",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F1B", Name ="Terminal Floor Limit",Length=4  , TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F1C", Name ="Terminal Identification",Length=8, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F1D", Name = "Terminal Risk Management Data",minLen=1,maxLen=8,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "9F35", Name ="Terminal Type",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "95",   Name ="Terminal Verification Results",Length=5, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "97",   Name = "Transaction Certificate Data Object List (TDOL)",minLen=0,maxLen=252,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "98",   Name ="Transaction Certificate (TC) Hash Value",Length=20,TagLengthRep=TagLengthType.Fixed},
                new TLV { Id = "5F2A", Name ="Transaction Currency Code",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "5F36", Name ="Transaction Currency Exponent",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9A",   Name ="Transaction Date",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "99",   Name = "Transaction Personal Identification Number (PIN) Data",TagLengthRep=TagLengthType.Variable},//->VAR
                new TLV { Id = "9F3C", Name ="Transaction Reference Currency Code",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F04", Name ="Amount,Other(Binary)",Length=4, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F03", Name = "Amount,Other(Numeric)",Length=6, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F3A", Name = "Amount,Reference Currency",Length=4, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F26", Name = "Application Cryptogram",Length=8, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F42", Name = "Application Currency Code",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F44", Name = "Application Currency Exponent",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F05", Name = "Application Discretionary Data",minLen=1,maxLen=32,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "5F25", Name = "Application Effective Date",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "5F24", Name = "Application Expiration Date",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "94",   Name = "Application File Locator (AFL)",minLen=0,maxLen=252,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "87",   Name = "Application Priority Indicator",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F3B", Name = "Application Reference Currency",minLen=2,maxLen=8,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "9F43", Name = "Application Reference Currency Exponent",minLen=1,maxLen=4,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "8A",   Name = "Authorisation Response Code",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "5F54", Name = "Bank Identifier Code (BIC)",minLen=8,maxLen=11,TagLengthRep=TagLengthType.OrNum},//OR
                new TLV { Id = "A1",   Name = "Biometric Header Template (BHT)",TagLengthRep= TagLengthType.Variable},//->VAR
                new TLV { Id = "7F60", Name = "Biometric Information Template (BIT)",TagLengthRep= TagLengthType.Variable},//-> VAR
                new TLV { Id = "9F31", Name = "Card BIT Group Template",TagLengthRep = TagLengthType.Variable},//-> VAR
                new TLV { Id = "BF4E", Name = "Biometric Verification Data Template",TagLengthRep = TagLengthType.Variable},//-> VAR
                new TLV { Id = "8C",   Name = "Card Risk Management Data Object List 1 (CDOL1)",minLen=0,maxLen=252, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "8D",   Name = "Card Risk Management Data Object List 2 (CDOL2)",minLen=0,maxLen=252, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "5F20", Name = "Cardholder Name",minLen=2,maxLen=26,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "83",   Name = "Command Template",TagLengthRep = TagLengthType.Variable},//->VAR
                new TLV { Id = "9F45", Name = "Data Authentication Code",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "84",   Name = "Dedicated File (DF) Name",minLen=5,maxLen=16, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "9D",   Name = "Directory Definition File (DDF) Name",minLen=5,maxLen=16, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "A5",   Name = "File Control Information (FCI) Proprietary Template",TagLengthRep = TagLengthType.Variable},//->VAR
                new TLV { Id = "6F",   Name = "File Control Information (FCI) Template",minLen=0,maxLen=252, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "9F4C", Name = "ICC Dynamic Number",minLen=2,maxLen=8,TagLengthRep= TagLengthType.Min_Max},
                new TLV { Id = "9F2D", Name = "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate (RSA)",Length=17, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "5F53", Name = "International Bank Account Number (IBAN)",minLen=0,maxLen=34, TagLengthRep = TagLengthType.Min_Max},
                new TLV { Id = "DF52", Name = "Iris Try Counter",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F0D", Name = "Issuer Action Code – Default",Length=5, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F0E", Name = "Issuer Action Code – Denial",Length=5, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F0F", Name = "Issuer Action Code – Online",Length=5, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F10", Name = "Issuer Application Data",minLen=0,maxLen=32,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "90",   Name = "Issuer Public Key Certificate",Length=21, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F32", Name = "Issuer Public Key Exponent",minLen=1,maxLen=3, TagLengthRep = TagLengthType.OrNum},//->Edit for OR
                new TLV { Id = "92",   Name = "Issuer Public Key Remainder",Length=36, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "86",   Name = "Issuer Script Command",minLen=0,maxLen=261,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "9F18", Name = "Issuer Script Identifier",Length=4, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "71",   Name = "Issuer Script Template 1",TagLengthRep= TagLengthType.Variable},//->VAR
                new TLV { Id = "72",   Name = "Issuer Script Template 2",TagLengthRep = TagLengthType.Variable},//->VAR
                new TLV { Id = "5F50", Name = "Issuer URL",TagLengthRep = TagLengthType.Variable},//->VAR
                new TLV { Id = "9F15", Name = "Merchant Category Code",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F16", Name = "Merchant Identifier",Length=15, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F4E", Name = "Merchant Name and Location",TagLengthRep = TagLengthType.Variable},//->VAR
                new TLV { Id = "BF4A", Name = "Offline BIT Group Template",TagLengthRep = TagLengthType.Variable},//->VAR
                new TLV { Id = "BF4D", Name = "Preferred Attempts Template23",TagLengthRep = TagLengthType.Variable},//-> VAR
                new TLV { Id = "DF50", Name = "Preferred Facial Attempts",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "DF51", Name = "Preferred Finger Attempts",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "DF52", Name = "Preferred Iris Attempt",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "DF53", Name = "Preferred Palm Attempts",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "DF54", Name = "Preferred Voice Attempts",Length=1, TagLengthRep = TagLengthType.Fixed},
              //new TLV { Id = "9F4B", Name = "Signed Dynamic Application Data",Length=0},//->ambiguity:Reason:unable to understand the length parameter(page.no:156)
              //new TLV { Id = "93",   Name = "Signed Static Application Data",Length=0},//->ambiguity:Reason:unable to understand the length parameter(page.no:156)
                new TLV { Id = "9F4A", Name = "Static Data Authentication Tag List",TagLengthRep = TagLengthType.Variable},//-VAR
                new TLV { Id = "9F19", Name = "Token Requestor ID",Length=6, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F1F", Name = "Track 1 Discretionary Data",TagLengthRep = TagLengthType.Variable},//-> VAR
                new TLV { Id = "9F20", Name = "Track 2 Discretionary Data",TagLengthRep = TagLengthType.Variable},//->VAR
                new TLV { Id = "9F3D", Name = "Transaction Reference Currency Exponent",Length=1,TagLengthRep=TagLengthType.Fixed},
                new TLV { Id = "9F41", Name = "Transaction Sequence Counter",minLen=2,maxLen=4,TagLengthRep=TagLengthType.Min_Max},
                new TLV { Id = "9B",   Name = "Transaction Status Information",Length=2, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F21", Name = "Transaction Time",Length=3, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9C",   Name = "Transaction Type",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "9F23", Name = "Upper Consecutive Offline Limit",Length=1, TagLengthRep = TagLengthType.Fixed},
                new TLV { Id = "DF54", Name = "Voice Try Counter",Length=1, TagLengthRep = TagLengthType.Fixed},
                               
               //Add more TLV objects as needed
               
            };

            List<TLV> Tags = ParseEMVData(emvData, emvTags);

            // Print the parsed tags
            Console.WriteLine("Tags are:\n");
            foreach (var tag in Tags)
            {
                Console.WriteLine($"Tag ID: {tag.Id}");
                Console.WriteLine($"Tag Length: {tag.Length}");
                Console.WriteLine($"Tag Name: {tag.Name}");
                Console.WriteLine($"Tag Value: {tag.Value}\n");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }

        Console.ReadLine();
    }

    static List<TLV> ParseEMVData(string emvData, List<TLV> emvTags)
    {
        List<TLV> Tags = new List<TLV>();
        int index = 0;

        while (index < emvData.Length)
        {
            string tagId = emvData.Substring(index, 2);
            index += 2;

            string tagIdSecondHalf = "";

            if (tagId == "9F" || tagId == "5F")
            {
                tagIdSecondHalf = emvData.Substring(index, 2);
                index += 2;
                tagId = tagId + tagIdSecondHalf;
            }
            string tagLengthStr = emvData.Substring(index, 2);
            int tagLengthValue = Convert.ToInt32(tagLengthStr, 16);
        
            TLV reqTagSpec = FindTag(emvTags, tagId);
            int a = Operation(reqTagSpec, tagId, tagLengthValue);
            index += 2;
            string tagValue = emvData.Substring(index, tagLengthValue * 2);
            index += tagLengthValue * 2;
            TLV emvTag = new TLV() { };
            if (a == 1)
            {
                emvTag = new TLV
                {
                    Id = tagId, // Use only the tagId without tagIdSecondHalf
                    Length = tagLengthValue,
                    Value = "Invalid Length given by the user",
                    Name = GetTagName(emvTags, tagId) // Get the name from the emvTags list
                };
            }
            else
            {
                emvTag = new TLV
                {
                    Id = tagId, // Use only the tagId without tagIdSecondHalf
                    Length = tagLengthValue,
                    Value = tagValue,
                    Name = GetTagName(emvTags, tagId) // Get the name from the emvTags list
                };
            }
            Tags.Add(emvTag);
        }
        return Tags;
    }

    static string GetTagName(List<TLV> emvTags, string tagId)
    {
        // Find the tag with the specified tagId and return its Name property
        var tag = emvTags.Find(t => t.Id == tagId);
        return tag?.Name ?? "";
    }
    private static TLV FindTag(List<TLV> tagSpecs, string tagId)
    {
        var tag = tagSpecs.Where(x => x.Id == tagId).FirstOrDefault();
        return tag;
    }
    private static int Operation(TLV reqTagSpec, string tagId, int tagLengthValue)
    {
        int a = 1;
        if (reqTagSpec != null)
        {
            if (reqTagSpec.Id == tagId)
            {
                if (reqTagSpec.TagLengthRep == TagLengthType.Variable)
                {
                    a = 0;

                }
                else if (reqTagSpec.TagLengthRep == TagLengthType.Fixed)
                {
                    if (reqTagSpec.Length == tagLengthValue)
                    {
                        a = 0;
                    }
                }
                else if (reqTagSpec.TagLengthRep == TagLengthType.Min_Max)
                {

                    if (tagLengthValue >= reqTagSpec.minLen && tagLengthValue <= reqTagSpec.maxLen)
                    {
                        a = 0;
                    }
                }
                else if (reqTagSpec.TagLengthRep == TagLengthType.OrNum)
                {
                    if (tagLengthValue == reqTagSpec.minLen || tagLengthValue == reqTagSpec.maxLen)
                    {
                        a = 0;
                    }
                }
            }
        }
        return a;
    }
}