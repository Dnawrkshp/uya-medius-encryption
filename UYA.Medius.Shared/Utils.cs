using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Text;

namespace UYA.Medius.Shared
{
    public static class Utils
    {
        public static byte[] Flip(byte[] buffer)
        {
            byte[] result = new byte[buffer.Length];
            for (int i = 0; i < result.Length; ++i)
                result[i] = buffer[buffer.Length - i - 1];

            return result;
        }

        public static byte[] ToBA(this BigInteger b)
        {
            return Flip(b.ToByteArrayUnsigned());
        }

        public static BigInteger ToBigInteger(this byte[] ba)
        {
            return new BigInteger(1, Flip(ba));
        }


        #region Hash

        public static byte[] Hash(byte[] input, MessageSignContext encryptionType)
        {
            byte[] result = new byte[4];
            Hash(input, 0, input.Length, result, 0, (byte)encryptionType);
            return result;
        }

        private static void Hash(
            byte[] input,
                int inOff,
                int length,
                byte[] output,
                int outOff,
                byte encryptionType)
        {
            byte[] result = new byte[20];

            // Compute sha1 hash
            Sha1Digest digest = new Sha1Digest();
            digest.BlockUpdate(input, inOff, length);
            digest.DoFinal(result, 0);

            // Extra operation that UYA wants
            result[3] = (byte)((result[3] & 0x1F) | ((encryptionType & 7) << 5));

            Array.Copy(result, 0, output, outOff, 4);
        }

        #endregion
    }
}
