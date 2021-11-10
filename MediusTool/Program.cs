using Medius.Crypto;
using MediusTool.Operations;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CommandLine;
using Newtonsoft.Json.Converters;
using Org.BouncyCastle.Math;
using System.Text;

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
            Console.OutputEncoding = Encoding.UTF8;

            if (false)
            {
                BigInteger pub = new BigInteger(1, Utils.BAFromStringFlipped("CF16B818A204BA6DB8FC85D866E4F708E6CFA754A5A2399D08EAFDFDBBFF852D3F1C86944E157DD8F6408D7CD9CFDAB409D32FDDEE05BDDE8CFF303187B37469".Replace(" ", "")));
                BigInteger priv = new BigInteger(1, Utils.BAFromStringFlipped("7CC5CCB73E8BFFB1888D870279767063A8EA2A619FDD3BBC0B1209B5384853408EC61AAFA8B9071F9E41AB93BB56DBCEA59EBF18CA113775FD146C3E97FB673D".Replace(" ", "")));

                Console.WriteLine(pub);
                Console.WriteLine(priv);


                RSA rsaTest = new RSA(pub, new BigInteger("17"), priv);

                byte[] plain = Encoding.ASCII.GetBytes("HELLO");
                bool a = rsaTest.Encrypt(plain, out var cipher, out var hash);

                bool b = rsaTest.Decrypt(cipher, hash, out var unsigned);

                Console.WriteLine($"Encrypt: {a}, Decrypt: {b}");
                Console.ReadLine();
            }


            // Load asymmetric keys
            if (File.Exists(ASYM_KEYS_PATH))
            {
                AsymmetricKeys = JsonConvert.DeserializeObject<List<RSA>>(File.ReadAllText(ASYM_KEYS_PATH));
                foreach (var rsa in AsymmetricKeys)
                {
                    Console.WriteLine(rsa.Comment);
                    Console.WriteLine($"N: {BitConverter.ToString(rsa.N.ToByteArrayUnsigned().ToArray()).Replace("-", "")}");
                    Console.WriteLine($"D: {BitConverter.ToString(rsa.D.ToByteArrayUnsigned().ToArray()).Replace("-", "")}");
                    PS3_AsymmetricKeys.Add(new PS3_RSA(rsa.N, rsa.E, rsa.D));
                }
            }

            // Load symmetric keys
            if (File.Exists(SYM_KEYS_PATH))
                SymmetricKeys = File.ReadAllLines(SYM_KEYS_PATH).ToList();

            Console.WriteLine("\n\n");
            return CommandLine.Parser.Default.ParseArguments<DecryptOp, EncryptSymmetricOp, DecryptSymmetricOp, DecryptStreamOp, DecryptPcapOp>(args)
               .MapResult(
                 (DecryptOp opts) => opts.Run(),
                 (EncryptSymmetricOp opts) => opts.Run(),
                 (DecryptSymmetricOp opts) => opts.Run(),
                 (DecryptStreamOp opts) => opts.Run(),
                 (DecryptPcapOp opts) => opts.Run(),
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
                if (!SymmetricCiphers.Any(x => x.Value.Any(y => y.Equals(cipher))))
                {
                    Console.WriteLine($"Added new symmetric key: {cipher.ToString()}");

                    SymmetricCiphers[cipher.Context].Add(cipher);
                }
            }
        }
    }
}
