using CommandLine;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using UYA.Medius.Shared;


namespace Medius
{
    class Program
    {
        static int Main(string[] args)
        {
            TestRSA.Handle92();
            Console.WriteLine();
            TestRSA.Handle93();
            Console.WriteLine("\n\n");


            byte[] raw = Utils.BAFromString("0108010100BC29000007CBF0876835BD72FE358D26ECDDB79F858A0CE1690DF49A19642D41B1B45A764A85586097AF6ABD65A1DAE4278E08848149F2EC6F2846FEAA039D4DE27D667F");
            byte[] signed = Utils.BAFromString("34424493f946c42c3dd10c2c492fef0ff8e829fd324e3f7cca9a4bac7459e041b10ccd500d57955fad539983ce099e65033e505766e78c24143d62978df74372");



            byte[] hash = Utils.BAFromString("666ed671");
            var rc4 = new RC4(Utils.BAFromString("60937E5CD170EF0B5E0DF26DD93D84F04723CEDA8946886A329C8BE407D82EFADB383517D488448D5CA6F5D5F0204DC7BF5100528CE0373B7FDE1AA379D59486"));
            byte[] ourSigned = rc4.Encrypt(raw);
            byte[] ourUnsigned = rc4.Decrypt(hash, signed);

            Console.Write($"0x80 RC4 SIGNED  : {signed.SequenceEqual(ourSigned)} {Utils.BAToString(ourSigned)}\n\n");
            Console.Write($"0x80 RC4 UNSIGNED: {ourUnsigned.SequenceEqual(raw)} {Utils.BAToString(ourUnsigned)} Hash:{RC4.Hash(ourUnsigned).SequenceEqual(hash)}\n\n");

            Console.ReadKey();
            return 0;


            return CommandLine.Parser.Default.ParseArguments<DecryptOptions, EncryptOptions>(args)
                .MapResult(
                  (DecryptOptions opts) => RunDecryptAndReturnExitCode(opts),
                  (EncryptOptions opts) => RunEncryptAndReturnExitCode(opts),
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
            byte[] keyBytes = Utils.BAFromString(key);
            byte[] packetBytes = Utils.BAFromString(packet);

            RC4 packer = new RC4(keyBytes);

            for (int i = 0; i < packetBytes.Length;)
            {
                byte id = packetBytes[i + 0];
                ushort len = BitConverter.ToUInt16(packetBytes, i + 1);
                byte[] hash = new byte[4];
                byte[] buf = new byte[len];
                Array.Copy(packetBytes, i + 7, buf, 0, len);
                Array.Copy(packetBytes, i + 3, hash, 0, 4);
                byte[] result = packer.Decrypt(hash, buf);

                string operationResult = (Convert.ToBase64String(RC4.Hash(result)) == Convert.ToBase64String(hash)) ? "SUCCESS" : "FAILURE";
                Console.WriteLine($"ID:{id.ToString("X2")} LEN:{len} SHA1:{Utils.BAToString(hash)} RESULT:{operationResult} DATA:");
                Utils.FancyPrintBA(result);
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
            byte[] keyBytes = Utils.BAFromString(key);
            byte[] messageBytes = Utils.BAFromString(message); // System.Text.Encoding.UTF8.GetBytes(message);
            byte[] cipher = new byte[messageBytes.Length];

            RC4 packer = new RC4(keyBytes);

            // TODO encrypt
            cipher = packer.Encrypt(messageBytes);
            
            // Output
            Console.WriteLine($"SHA1:{Utils.BAToString(RC4.Hash(messageBytes))} CIPHER:{Utils.BAToString(cipher)}");
            Console.WriteLine();
        }

        #endregion

    }
}
