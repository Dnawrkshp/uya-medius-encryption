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
    [Verb("decrypt", HelpText = "Decrypt packet")]
    class DecryptOp
    {
        [Option('p', "packet", Required = true, HelpText = "Packet as a hexstring.")]
        public string Packet { get; set; }

        [Option('v', "version", Required = true, Default = Versions.PS2_UYA, HelpText = "PS2_UYA|PS3")]
        public Versions Version { get; set; }


        #region Decrypt Packet

        public int Run()
        {
            _decryptPacket(Packet);
            return 0;
        }

        void _decryptPacket(string packet)
        {
            byte[] packetBytes = Utils.BAFromString(packet);

            // populate collection of ciphers
            IEnumerable<ICipher> asymCiphers = Program.AsymmetricKeys.Select(x => x as ICipher);
            Program.CreateBruteforceCiphers(Version);

            try
            {
                var messages = BaseMessage.InstantiateBruteforce(packetBytes, (id, context) =>
                {
                    switch (context)
                    {
                        case CipherContext.RSA_AUTH: return asymCiphers;
                        default: return Program.SymmetricCiphers[context];
                    }

                });


                foreach (var msg in messages)
                {
                    Console.WriteLine($"[SUCCESS] ID:{msg.Id} PLAINTEXT: ");
                    Utils.FancyPrintBA((msg as RawMessage).Contents);
                    Console.WriteLine();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        #endregion

    }
}
