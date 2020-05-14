using CommandLine;
using Newtonsoft.Json;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UYA.Medius.Shared;


namespace Medius
{
    class Program
    {
        static List<RSA> RSAKeys = new List<RSA>();
        static int Main(string[] args)
        {
            RSAKeys = JsonConvert.DeserializeObject<List<RSA>>(File.ReadAllText("rsa_keys.txt"));

            //if (false)
            //{
            //    byte[] key = StringUtils.BAFromString("42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242");
            //    byte[] input = StringUtils.BAFromString("B144DB89878DAC11D91A6060E85874BCBE6FB1AF58555736153FC5BFD8C4E7333C17FE4A712F8B89DC0AE910C880B71B6DE58F5A5B2073401643ED1D45C89672A8A2725B0E3A8385");
            //    byte[] hash = StringUtils.BAFromString("DEC35461");
            //    //Utils.HashPS3_Flip(input);

            //    // hash = C154C3DE
            //    // signed = 89DB44B111AC8D8760601AD9BC7458E8AFB16FBE36575558BFC53F1533E7C4D84AFE173C898B2F7110E90ADC1BB780C85A8FE56D4073205B1DED43167296C8455B72A2A885833A0E

            //    RCQ rcq = new RCQ();
            //    rcq.SetKey(key, MessageSignContext.Session);

            //    //Console.Write(StringUtils.BAToString(input) + " => ");
            //    //if (rcq.Encrypt(input, out var hash))
            //    //    Console.WriteLine(StringUtils.BAToString(hash) + " " + StringUtils.BAToString(input));
            //    //else
            //    //    Console.WriteLine("FAILED");

            //    Console.Write(StringUtils.BAToString(input) + " => ");
            //    if (rcq.Decrypt(input, hash, out var plain))
            //        Console.WriteLine(StringUtils.BAToString(plain));
            //    else
            //        Console.WriteLine("FAILED");

            //    // a30100 376f8c66 38
            //    // a10200 356e8c66 03e4

            //    Console.WriteLine("Done");
            //    Console.ReadKey();
            //    return 0;
            //}

            return CommandLine.Parser.Default.ParseArguments<DecryptOptions, EncryptOptions, DecryptStreamOptions>(args)
                .MapResult(
                  (DecryptOptions opts) => RunDecryptAndReturnExitCode(opts),
                  (EncryptOptions opts) => RunEncryptAndReturnExitCode(opts),
                  (DecryptStreamOptions opts) => RunDecryptStreamAndReturnExitCode(opts),
                  errs => 1);
        }

        static int RunDecryptAndReturnExitCode(DecryptOptions opts)
        {
            Console.WriteLine();
            DecryptPacket(opts.Key, opts.Packet);

#if DEBUG
            Console.ReadKey();
#endif

            return 0;
        }

        static int RunEncryptAndReturnExitCode(EncryptOptions opts)
        {
            Console.WriteLine();
            EncryptMessage(opts.Key, opts.Message);

#if DEBUG
            Console.ReadKey();
#endif

            return 1;
        }


        static int RunDecryptStreamAndReturnExitCode(DecryptStreamOptions opts)
        {
            CipherContext context = new CipherContext()
            {
                // the private exponent is not correct for decrypting the 92 packet
                // but the public and mod work for encrypting them
                // we also know that the key sent in the 92 packet is a constant that is always equal to
                // 6B8F99EC1BAF06D2674284B5305EE6E38B1DE7331F2FBF31DE497228B7C52162F18DAE8913C40C43C0E890D14EEE16AD07C64FD9281D8B972D78BE78D1B290CE
                // for UYA NTSC
                MASConnectCipher = null,

                // This keypair decrypts the 93 packet sent from the server to the client
                // The 93 packet contains the session key used to encrypt all future packets
                MASResponseCipher = null
            };
            
            byte[] unsignedData = null;
            byte[] hash = null;

            try
            {
                string[] lines = File.ReadAllLines(opts.Filepath);
                foreach (var line in lines)
                {
                    if (line != String.Empty && !line.StartsWith("//"))
                    {
                        // Read
                        var rawMessages = RawMessage.FromString(line);

                        foreach (var rawMessage in rawMessages)
                        {
                            // Reset
                            unsignedData = null;
                            hash = null;

                            // Parse
                            switch (rawMessage.Id)
                            {
                                // CLIENT AUTH
                                case MessageId.ID_12:
                                    {
                                        FindDecryptRSA(ref context.MASConnectCipher, RSAKeys, rawMessage, out unsignedData);
                                        break;
                                    }
                                // SESSION KEY
                                case MessageId.ID_13:
                                    {
                                        if (FindDecryptRSA(ref context.MASResponseCipher, RSAKeys, rawMessage, out unsignedData))
                                            context.SessionCipher = new RCQ(unsignedData, MessageSignContext.Session);
                                        break;
                                    }
                                case MessageId.ID_14:
                                    {
                                        unsignedData = rawMessage.Unsign(context);
                                        context.Cipher94 = new RCQ(unsignedData, MessageSignContext.UNK_94);
                                        break;
                                    }
                                default:
                                    {
                                        unsignedData = rawMessage.Unsign(context);
                                        break;
                                    }
                            }

                            if (unsignedData != null)
                            {
                                if (rawMessage.Signed)
                                {
                                    hash = Utils.HashPS3(unsignedData, rawMessage.SignType);
                                    bool match = Convert.ToBase64String(rawMessage.Hash) == Convert.ToBase64String(hash);
                                    Console.Write("[" + (match ? "SUCCESS" : "FAILURE") + "] ");
                                }

                                Console.Write($"{rawMessage.Id} {(rawMessage.Signed ? rawMessage.SignType.ToString() : "")} {rawMessage.Data.Length.ToString("X2")} {StringUtils.BAToString(rawMessage.Hash)} {StringUtils.BAToString(rawMessage.Data)} => ");
                                StringUtils.FancyPrintBA(unsignedData);
                                Console.WriteLine();
                            }
                            else
                            {
                                Console.WriteLine($"[FAILURE] {rawMessage.Id} {(rawMessage.Signed ? rawMessage.SignType.ToString() : "")} {rawMessage.Data.Length.ToString("X2")} {StringUtils.BAToString(rawMessage.Hash)} {StringUtils.BAToString(rawMessage.Data)}");
                                Console.WriteLine();
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

#if DEBUG
            Console.ReadKey();
#endif

            return 1;
        }

        static bool FindDecryptRSA(ref ICipher cipher, List<RSA> rsaKeys, RawMessage message, out byte[] plain)
        {
            if (!message.Signed)
            {
                plain = message.Data;
                return true;
            }


            foreach (var rsa in rsaKeys)
            {
                try
                {
                    if (rsa.Decrypt(message.Data, message.Hash, out plain))
                    {
                        cipher = rsa;
                        return true;
                    }
                }
                catch (Exception)
                {

                }
            }

            plain = null;
            return false;
        }

        #region Decrypt Packet

        static void DecryptPacket(string key, string packet)
        {
            if (key != null)
            {
                _decryptPacket(key, packet);
                return;
            }

            string[] keys = System.IO.File.ReadAllLines("keys.txt");

            for (int k = 0; k < keys.Length; ++k)
            {
                Console.WriteLine($"DECRYPTING WITH KEY:{keys[k]}");
                Console.WriteLine();

                _decryptPacket(keys[k], packet);

                Console.WriteLine();
                Console.WriteLine();
            }
        }

        static void _decryptPacket(string key, string packet)
        {
            byte[] keyBytes = StringUtils.BAFromString(key);
            byte[] packetBytes = StringUtils.BAFromString(packet);

            RC4 packer = new RC4(keyBytes, MessageSignContext.Session);

            for (int i = 0; i < packetBytes.Length;)
            {
                byte id = packetBytes[i + 0];
                ushort len = BitConverter.ToUInt16(packetBytes, i + 1);
                byte[] hash = new byte[4];
                byte[] buf = new byte[len];
                Array.Copy(packetBytes, i + 7, buf, 0, len);
                Array.Copy(packetBytes, i + 3, hash, 0, 4);
                bool result = packer.Decrypt(hash, buf, out var plain);

                string operationResult = (Convert.ToBase64String(Utils.Hash(plain, MessageSignContext.Session)) == Convert.ToBase64String(hash)) ? "SUCCESS" : "FAILURE";
                Console.WriteLine($"ID:{id.ToString("X2")} LEN:{len} SHA1:{StringUtils.BAToString(hash)} RESULT:{operationResult} DATA:");
                StringUtils.FancyPrintBA(plain);
                Console.WriteLine();

                i += len + 7;
            }
        }

        #endregion

        #region Encrypt Message

        static void EncryptMessage(string key, string message)
        {
            if (key != null)
            {
                _encryptMessage(key, message);
                return;
            }

            string[] keys = System.IO.File.ReadAllLines("keys.txt");
            for (int k = 0; k < keys.Length; ++k)
            {
                Console.WriteLine($"ENCRYPTING WITH KEY:{keys[k]}");
                Console.WriteLine();

                _encryptMessage(keys[k], message);

                Console.WriteLine();
                Console.WriteLine();
            }
        }

        static void _encryptMessage(string key, string message)
        {
            byte[] keyBytes = StringUtils.BAFromString(key);
            byte[] messageBytes = StringUtils.BAFromString(message); // System.Text.Encoding.UTF8.GetBytes(message);
            byte[] cipher = new byte[messageBytes.Length];

            RC4 packer = new RC4(keyBytes, MessageSignContext.Session);

            // TODO encrypt
            bool result = packer.Encrypt(messageBytes, out cipher, out var hash);
            
            // Output
            Console.WriteLine($"SHA1:{StringUtils.BAToString(hash)} CIPHER:{StringUtils.BAToString(cipher)}");
            Console.WriteLine();
        }

        #endregion
        
    }
}
