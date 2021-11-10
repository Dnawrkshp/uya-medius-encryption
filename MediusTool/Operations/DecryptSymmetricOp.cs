using CommandLine;
using Medius.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MediusTool.Operations
{
    [Verb("decrypt-symmetric", HelpText = "Decrypt message with symmetric cipher")]
    class DecryptSymmetricOp
    {
        [Option('k', "key", Required = true, HelpText = "Symmetric key as a hexstring (64 bytes).")]
        public string Key { get; set; }

        [Option('m', "message", Required = true, HelpText = "Message as hexstring.")]
        public string Message { get; set; }

        [Option('v', "version", Required = true, Default = Versions.PS2_UYA, HelpText = "PS2_UYA|PS3")]
        public Versions Version { get; set; }


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

            var id = messageBytes[0];
            var len = BitConverter.ToUInt16(messageBytes, 1);
            byte[] cipherText = new byte[len];
            byte[] hash = null;

            Array.Copy(messageBytes, 3 + (id >= 0x80 ? 4 : 0), cipherText, 0, len);

            if (id >= 0x80)
            {
                hash = new byte[4];
                Array.Copy(messageBytes, 3, hash, 0, 4);
            }

            var context = (CipherContext)(hash[3] >> 5);

            switch (Version)
            {
                case Versions.PS2_UYA:
                    {
                        cipher = new PS2_UYA_RC4(keyBytes, context);
                        break;
                    }
                case Versions.PS3:
                    {
                        cipher = new PS3_RC(keyBytes, context);
                        break;
                    }
            }


            if (cipher.Decrypt(cipherText, hash, out var plainText))
            {
                Console.WriteLine($"SUCCESS: {Utils.BAToString(plainText)}");
            }
            else
            {
                Console.WriteLine($"FAILED: {Utils.BAToString(plainText)}");
            }
        }

        #endregion

    }
}
