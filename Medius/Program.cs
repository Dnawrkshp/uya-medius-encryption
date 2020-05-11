using CommandLine;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using UYA.Medius.Shared;


namespace Medius
{
    class Program
    {
        static int Main(string[] args)
        {
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
                MASConnectCipher = new RSA(
                    // modulus
                    new BigInteger("10315955513017997681600210131013411322695824559688299373570246338038100843097466504032586443986679280716603540690692615875074465586629501752500179100369237", 10),

                    // public exp
                    new BigInteger("17", 10),

                    // private exp
                    new BigInteger("4854567300243763614870687120476899445974505675147434999327174747312047455575182761195687859800492317495944895566174677168271650454805328075020357360662513", 10)
                    ),

                // This keypair decrypts the 93 packet sent from the server to the client
                // The 93 packet contains the session key used to encrypt all future packets
                MASResponseCipher = new RSA(
                    // mod
                    new BigInteger("CE90B2D178BE782D978B1D28D94FC607AD16EE4ED190E8C0430CC41389AE8DF16221C5B7287249DE31BF2F1F33E71D8BE3E65E30B5844267D206AF1BEC998F6B", 16),

                    // public exp
                    new BigInteger("11", 16),

                    // private exp
                    new BigInteger("85A8EC2D3002C63B9E4AF4C014248F3224B47C14E1F45A5E4980BB1BB370F26DD8B80978FC2DCEC8B28563F1659A00B65C843D20732D3773E6AA95C37F9D5511", 16)
                    )
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
                                        // decryption not supported
                                        // but for UYA NTSC we know this value to be
                                        // 6B8F99EC1BAF06D2674284B5305EE6E38B1DE7331F2FBF31DE497228B7C52162F18DAE8913C40C43C0E890D14EEE16AD07C64FD9281D8B972D78BE78D1B290CE
                                        break;
                                    }
                                // SESSION KEY
                                case MessageId.ID_13:
                                    {
                                        unsignedData = rawMessage.Unsign(context);
                                        context.SessionCipher = new RC4(unsignedData, MessageSignContext.Session);
                                        break;
                                    }
                                case MessageId.ID_14:
                                    {
                                        unsignedData = rawMessage.Unsign(context);
                                        context.Cipher94 = new RC4(unsignedData, MessageSignContext.UNK_94);
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
                                    hash = Utils.Hash(unsignedData, rawMessage.SignType);
                                    bool match = Convert.ToBase64String(rawMessage.Hash) == Convert.ToBase64String(hash);
                                    Console.Write("[" + (match ? "SUCCESS" : "FAILURE") + "] ");
                                }

                                Console.Write($"{rawMessage.Id} {(rawMessage.Signed ? rawMessage.SignType.ToString() : "")} {rawMessage.Data.Length} {StringUtils.BAToString(rawMessage.Hash)} {StringUtils.BAToString(rawMessage.Data)} => ");
                                StringUtils.FancyPrintBA(unsignedData);
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
                byte[] result = packer.Decrypt(hash, buf);

                string operationResult = (Convert.ToBase64String(Utils.Hash(result, MessageSignContext.Session)) == Convert.ToBase64String(hash)) ? "SUCCESS" : "FAILURE";
                Console.WriteLine($"ID:{id.ToString("X2")} LEN:{len} SHA1:{StringUtils.BAToString(hash)} RESULT:{operationResult} DATA:");
                StringUtils.FancyPrintBA(result);
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
            cipher = packer.Encrypt(messageBytes);
            
            // Output
            Console.WriteLine($"SHA1:{StringUtils.BAToString(Utils.Hash(messageBytes, MessageSignContext.Session))} CIPHER:{StringUtils.BAToString(cipher)}");
            Console.WriteLine();
        }

        #endregion
        
    }
}
