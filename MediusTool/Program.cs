using Medius.Crypto;
using MediusTool.Operations;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CommandLine;
using Newtonsoft.Json.Converters;

namespace MediusTool
{
    class Program
    {
        public const string SYM_KEYS_PATH = "Keys/sym_keys.txt";
        public const string ASYM_KEYS_PATH = "Keys/asym_keys.txt";

        // Collection of known asymmetric keys
        public static List<RSA> AsymmetricKeys = new List<RSA>();
        public static List<PS3_RSA> PS3_AsymmetricKeys = new List<PS3_RSA>();

        // 
        public static Dictionary<CipherContext, List<ICipher>> SymmetricCiphers = new Dictionary<CipherContext, List<ICipher>>();

        // Collection of known symmetric keys
        public static List<string> SymmetricKeys = new List<string>();

        static int Main(string[] args)
        {
            // Load asymmetric keys
            if (File.Exists(ASYM_KEYS_PATH))
            {
                AsymmetricKeys = JsonConvert.DeserializeObject<List<RSA>>(File.ReadAllText(ASYM_KEYS_PATH));
                foreach (var rsa in AsymmetricKeys)
                    PS3_AsymmetricKeys.Add(new PS3_RSA(rsa.N, rsa.E, rsa.D));
            }

            // Load symmetric keys
            if (File.Exists(SYM_KEYS_PATH))
                SymmetricKeys = File.ReadAllLines(SYM_KEYS_PATH).ToList();

            return CommandLine.Parser.Default.ParseArguments<DecryptOp, EncryptSymmetricOp, DecryptStreamOp>(args)
               .MapResult(
                 (DecryptOp opts) => opts.Run(),
                 (EncryptSymmetricOp opts) => opts.Run(),
                 (DecryptStreamOp opts) => opts.Run(),
                 errs => 1);
        }

        public static void CreateBruteforceCiphers(Versions version)
        {
            // 
            for (CipherContext context = 0; context < CipherContext.RSA_AUTH; ++context)
            {
                List<ICipher> ciphers = new List<ICipher>();
                foreach (var symKey in Program.SymmetricKeys)
                {
                    var keyBytes = Utils.BAFromString(symKey);

                    switch (version)
                    {
                        case Versions.PS2_UYA:
                            {
                                ciphers.Add(new PS2_UYA_RC4(keyBytes, context));
                                break;
                            }
                        case Versions.PS3:
                            {
                                ciphers.Add(new PS3_RC(keyBytes, context));
                                break;
                            }
                    }
                }

                SymmetricCiphers.Add(context, ciphers);
            }
        }

        public static void AddSymmetricCiphers(IEnumerable<ICipher> ciphers)
        {
            foreach (var cipher in ciphers)
            {
                if (!SymmetricCiphers.Any(x => x.Value.Equals(cipher)))
                {
                    SymmetricCiphers[cipher.Context].Add(cipher);
                }
            }
        }
    }
}
