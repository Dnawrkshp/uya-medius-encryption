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

        #region Hash
        
        public static byte[] HashPS3(byte[] input, MessageSignContext? encryptionType, bool sign = false)
        {
            uint r0 = 0x00000000;
            uint r3 = 0x5B3AA654;
            uint r5 = 0x75970A4D;
            uint r6 = (uint)input.Length;

            int newLength = (input.Length % 4 != 0) ? (input.Length + (4 - (input.Length % 4))) : input.Length;
            byte[] buffer = new byte[newLength];
            Array.Copy(input, 0, buffer, 0, input.Length);
            HashPS3_Flip(buffer);

            // Seed
            byte[] empty = new byte[0x10];
            uint[] seed = new uint[4];
            HashPS3_Seeded(empty, ref seed);

            // B5A0559C 88AA4C20 013D2CC7 CB2DE2B6
            uint r16 = seed[0];
            uint r17 = seed[1];
            uint r18 = seed[2];
            uint r19 = seed[3];

            for (int i = 0; i < input.Length; i += 4)
            {
                r19 ^= r3;
                r18 += r16;
                r18 += r19;
                r18 = (r18 << 7) | (r18 >> (32 - 7));
                r17 += r19;
                r17 += r18;
                r18 ^= r5;
                r17 = (r17 << 11) | (r17 >> (32 - 11));
                r16 += r18;
                r16 += r17;
                r16 = (r16 >> 15) | (r16 << (32 - 15));
                r0 = r16 & r17;
                r17 = ~r17;
                r6 = r18 & r17;
                r0 |= r6;
                r19 += r0;
                r16 = ~r16;

                r0 = (uint)((buffer[i + 0] << 24) | (buffer[i + 1] << 16) | (buffer[i + 2] << 8) | (buffer[i + 3] << 0));
                r19 ^= r0;

                if (sign)
                {
                    byte[] r19_b = BitConverter.GetBytes(r19);
                    buffer[i + 0] = r19_b[0];
                    buffer[i + 1] = r19_b[1];
                    buffer[i + 2] = r19_b[2];
                    buffer[i + 3] = r19_b[3];
                }
            }

            uint hash = r16 + r17 + r18 + r19;
            if (encryptionType.HasValue)
                hash = (uint)(((ulong)(hash & 0x1FFFFFFF) | (ulong)encryptionType << 29));
            return BitConverter.GetBytes(hash);
        }

        public static void HashPS3_Flip(byte[] input)
        {
            for (int i = 0; i < input.Length; i += 4)
            {
                var temp = input[i + 0];
                input[i + 0] = input[i + 3];
                input[i + 3] = temp;
                temp = input[i + 1];
                input[i + 1] = input[i + 2];
                input[i + 2] = temp;
            }
        }

        public static uint HashPS3_Seeded(byte[] input, ref uint[] seed, bool sign = false)
        {
            uint r0 = 0x00000000;
            uint r3 = 0x5B3AA654;
            uint r5 = 0x75970A4D;
            uint r6 = 0x00000000;

            // 
            int newLength = (input.Length % 4 != 0) ? (input.Length + (4 - (input.Length % 4))) : input.Length;
            byte[] buffer = new byte[newLength];
            Array.Copy(input, 0, buffer, 0, input.Length);
            HashPS3_Flip(buffer);

            // B5A0559C 88AA4C20 013D2CC7 CB2DE2B6
            uint r16 = seed[0];
            uint r17 = seed[1];
            uint r18 = seed[2];
            uint r19 = seed[3];

            for (int i = 0; i < input.Length; i += 4)
            {
                r19 ^= r3;
                r18 += r16;
                r18 += r19;
                r18 = (r18 << 7) | (r18 >> (32 - 7));
                r17 += r19;
                r17 += r18;
                r18 ^= r5;
                r17 = (r17 << 11) | (r17 >> (32 - 11));
                r16 += r18;
                r16 += r17;
                r16 = (r16 >> 15) | (r16 << (32 - 15));
                r0 = r16 & r17;
                r17 = ~r17;
                r6 = r18 & r17;
                r0 |= r6;
                r19 += r0;
                r16 = ~r16;

                r0 = (uint)((buffer[i + 0] << 24) | (buffer[i + 1] << 16) | (buffer[i + 2] << 8) | (buffer[i + 3] << 0));
                r19 ^= r0;

                if (sign)
                {
                    byte[] r19_b = BitConverter.GetBytes(r19);
                    buffer[i + 0] = r19_b[0];
                    buffer[i + 1] = r19_b[1];
                    buffer[i + 2] = r19_b[2];
                    buffer[i + 3] = r19_b[3];
                }
            }

            seed[0] = r16;
            seed[1] = r17;
            seed[2] = r18;
            seed[3] = r19;

            if (sign)
                for (int i = 0; i < input.Length; ++i)
                    input[i] = buffer[i];

            return (uint)(r16 + r17 + r18 + r19);
        }

        #endregion
    }
}
