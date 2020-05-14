using CommandLine;
using Medius.Crypto;
using Medius.Shared.Message;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MediusTool.Operations
{
    [Verb("decrypt-stream", HelpText = "Decrypt a collection of medius messages")]
    class DecryptStreamOp
    {
        [Option('f', "filepath", Required = true, HelpText = "Path to file containing collection of medius messages.")]
        public string Filepath { get; set; }

        [Option('v', "version", Required = true, Default = Versions.PS2_UYA, HelpText = "PS2_UYA|PS3")]
        public Versions Version { get; set; }

        public int Run()
        {
            // populate collection of ciphers
            IEnumerable<ICipher> asymCiphers = null;
            switch (Version)
            {
                case Versions.PS2_UYA: { asymCiphers = Program.AsymmetricKeys.Select(x => x as ICipher); break; }
                case Versions.PS3: { asymCiphers = Program.PS3_AsymmetricKeys.Select(x => x as ICipher); break; }
            }

            Program.CreateBruteforceCiphers(Version);

            try
            {
                string[] lines = File.ReadAllLines(Filepath);
                foreach (var line in lines)
                {
                    if (line != String.Empty && !line.StartsWith("//"))
                    {
                        // Read
                        var msgBuffer = Utils.BAFromString(line);

                        try
                        {
                            var messages = BaseMessage.InstantiateBruteforce(msgBuffer, (id, context) =>
                            {
                                switch (context)
                                {
                                    case CipherContext.RSA_AUTH: return asymCiphers;
                                    default: return Program.SymmetricCiphers[context];
                                }

                            });


                            foreach (var msg in messages)
                            {
                                var rawMessage = msg as RawMessage;

                                // Parse
                                switch (msg.Id)
                                {
                                    // CLIENT AUTH
                                    case MessageIds.ID_12:
                                        {

                                            break;
                                        }
                                    // SESSION KEY
                                    case MessageIds.ID_13:
                                        {
                                            AddNewSymmetric(rawMessage.Contents);
                                            break;
                                        }
                                    case MessageIds.ID_14:
                                        {
                                            AddNewSymmetric(rawMessage.Contents);
                                            break;
                                        }
                                    default:
                                        {

                                            break;
                                        }
                                }

                                Console.WriteLine($"[SUCCESS] ID:{msg.Id} PLAINTEXT: ");
                                Utils.FancyPrintBA((msg as RawMessage).Contents);
                                Console.WriteLine();
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                            Console.WriteLine();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine();
            }

            return 0;
        }

        void AddNewSymmetric(byte[] key)
        {
            List<ICipher> ciphers = new List<ICipher>();

            for (CipherContext context = 0; context < CipherContext.RSA_AUTH; ++context)
            {
                switch (Version)
                {
                    case Versions.PS2_UYA:
                        {
                            ciphers.Add(new PS2_UYA_RC4(key, context));
                            break;
                        }
                    case Versions.PS3:
                        {
                            ciphers.Add(new PS3_RC(key, context));
                            break;
                        }
                }
            }
        }
    }
}
