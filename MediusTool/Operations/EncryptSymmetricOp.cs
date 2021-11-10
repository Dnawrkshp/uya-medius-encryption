using CommandLine;
using Medius.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace MediusTool.Operations
{
    [Verb("encrypt-symmetric", HelpText = "Encrypt message with symmetric cipher")]
    class EncryptSymmetricOp
    {
        [Option('k', "key", Required = true, HelpText = "Symmetric key as a hexstring (64 bytes).")]
        public string Key { get; set; }

        [Option('m', "message", Required = true, HelpText = "Message as hexstring.")]
        public string Message { get; set; }

        [Option('v', "version", Required = true, Default = Versions.PS2_UYA, HelpText = "PS2_UYA|PS3")]
        public Versions Version { get; set; }

        [Option('c', "context", Required = false, Default = CipherContext.RC_CLIENT_SESSION, HelpText = "Key context. This informs the recipient which key (from handshake) to use to decrypt it.")]
        public CipherContext Context { get; set; }


        #region Encrypt Message

        public int Run()
        {
            _encryptMessage(Key, Message);
            return 0;
        }

        void _encryptMessage(string key, string message)
        {
            byte[] keyBytes = Utils.BAFromString(key);
            byte[] messageBytes = Utils.BAFromString(message);
            ICipher cipher = null;

            switch (Version)
            {
                case Versions.PS2_UYA:
                    {
                        cipher = new PS2_UYA_RC4(keyBytes, Context);
                        break;
                    }
                case Versions.PS3:
                    {
                        cipher = new PS3_RC(keyBytes, Context);
                        break;
                    }
            }


            if (cipher.Encrypt(messageBytes, out var cipherBytes, out var hash))
            {
                // Output
                Console.WriteLine($"HASH:{Utils.BAToString(hash)} CIPHER:{Utils.BAToString(cipherBytes)}");
                Console.WriteLine();

                // Decrypt it again to ensure success
                if (cipher.Decrypt(cipherBytes, hash, out var plain))
                    Console.WriteLine($"DECRYPTED: {Utils.BAToString(plain)}");
                else
                    Console.WriteLine("FAILED TO DECRYPT ENCRYPTED CIPHERTEXT");
            }
            else
            {
                Console.WriteLine("FAILED");
            }
        }

        #endregion

    }
}
