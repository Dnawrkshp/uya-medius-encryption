using CommandLine;
using System;
using UYA.Medius.Shared;

namespace Medius
{
    class Program
    {
        static int Main(string[] args)
        {
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

                Console.WriteLine($"ID:{id.ToString("X2")} LEN:{len} SHA1:{Utils.BAToString(hash)} DATA:");
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
            Console.WriteLine($"SHA1:{Utils.BAToString(packer.Hash(messageBytes))} CIPHER:{Utils.BAToString(cipher)}");
            Console.WriteLine();
        }

        #endregion

    }
}
