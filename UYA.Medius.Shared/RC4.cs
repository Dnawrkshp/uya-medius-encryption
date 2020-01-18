using Org.BouncyCastle.Crypto.Digests;
using System;

namespace UYA.Medius.Shared
{
    /// <summary>
    /// UYA's custom RC4 implementation,
    /// based off https://github.com/bcgit/bc-csharp/blob/f18a2dbbc2c1b4277e24a2e51f09cac02eedf1f5/crypto/src/crypto/engines/RC4Engine.cs
    /// </summary>
    public class RC4
    {
        private readonly static int STATE_LENGTH = 256;

        /*
        * variables to hold the state of the RC4 engine
        * during encryption and decryption
        */
        private byte[] engineState;
        private int x;
        private int y;
        private byte[] workingKey;

        /// <summary>
        /// Initialize with key.
        /// UYA wants a 512 bit key.
        /// </summary>
        public RC4(byte[] key)
        {
            SetKey(key);
        }

        #region Initialization

        public void Reset()
        {
            SetKey(workingKey);
        }

        private void SetKey(byte[] keyBytes)
        {
            SetKey(keyBytes, null);
        }

        private void SetKey(byte[] key, byte[] hash = null)
        {
            workingKey = key;

            x = 0;
            y = 0;

            int keyIndex = 0;
            int li = 0;
            int cipherIndex = 0;
            int idIndex = 0;


            // Initialize engine state
            if (engineState == null)
                engineState = new byte[STATE_LENGTH];


            // reset the state of the engine
            // Normally this initializes values 0,1..254,255 but UYA does this in reverse.
            for (int i = 0; i < STATE_LENGTH; i++)
                engineState[i] = (byte)((STATE_LENGTH - 1) - i);

            if (hash != null && hash.Length == 4)
            {
                // Apply hash
                do
                {
                    int v1 = hash[idIndex];
                    idIndex = (idIndex + 1) & 3;

                    byte temp = engineState[cipherIndex];
                    v1 += li;
                    li = (temp + v1) & 0xFF;

                    engineState[cipherIndex] = engineState[li];
                    engineState[li] = temp;

                    cipherIndex = (cipherIndex + 5) & 0xFF;

                } while (cipherIndex != 0);

                // Reset
                keyIndex = 0;
                li = 0;
                cipherIndex = 0;
                idIndex = 0;
            }

            // Apply key
            do
            {
                int keyByte = key[keyIndex];
                keyByte += li;
                keyIndex += 1;
                keyIndex &= 0x3F;

                int cipherByte = engineState[cipherIndex];
                byte cipherValue = (byte)(cipherByte & 0xFF);



                cipherByte += keyByte;
                li = cipherByte & 0xFF;

                byte t0 = engineState[li];
                engineState[cipherIndex] = t0;
                engineState[li] = cipherValue;


                cipherIndex += 3;
                cipherIndex &= 0xFF;
            } while (cipherIndex != 0);
        }

        #endregion

        #region Decrypt

        private void Decrypt(
                byte[] input,
                int inOff,
                int length,
                byte[] output,
                int outOff)
        {

            for (int i = 0; i < length; ++i)
            {
                y = (y + 5) % 0xFF;

                int v0 = engineState[y];
                byte a2 = (byte)(v0 & 0xFF);
                v0 += x;
                x = (byte)(v0 & 0xFF);

                v0 = engineState[x];
                engineState[y] = (byte)(v0 & 0xFF);
                engineState[x] = a2;



                byte a0 = input[i];

                v0 += a2;
                v0 &= 0xFF;
                int v1 = engineState[v0];

                a0 ^= (byte)v1;
                output[i] = a0;


                v1 = engineState[a0] + x;
                x = v1 & 0xFF;
            }
        }

        public byte[] Decrypt(byte[] hash, byte[] data)
        {
            // Set seed
            SetKey(workingKey, hash);

            byte[] result = new byte[data.Length];
            Decrypt(data, 0, data.Length, result, 0);
            return result;
        }

        #endregion

        #region Hash

        public byte[] Hash(byte[] input)
        {
            byte[] result = new byte[4];
            Hash(input, 0, input.Length, result, 0);
            return result;
        }

        private void Hash(
            byte[] input,
                int inOff,
                int length,
                byte[] output,
                int outOff)
        {
            byte[] result = new byte[20];

            // Compute sha1 hash
            Sha1Digest digest = new Sha1Digest();
            digest.BlockUpdate(input, inOff, length);
            digest.DoFinal(result, 0);

            // Extra operation that UYA wants
            result[3] = (byte)((result[3] & 0x1F) | 0x60);

            Array.Copy(result, 0, output, outOff, 4);
        }

        #endregion

        #region Encrypt


        #region Decrypt

        private void Encrypt(
                byte[] input,
                int inOff,
                int length,
                byte[] output,
                int outOff)
        {

            for (int i = 0; i < length; ++i)
            {
                y = (y + 5) % 0xFF;

                int v0 = engineState[y];
                byte a1 = (byte)(v0 & 0xFF);
                x = (x + v0) & 0xFF;

                v0 = engineState[x];
                engineState[y] = (byte)v0;
                engineState[x] = a1;

                byte a2 = input[i];
                v0 = (v0 + a1) & 0xFF;

                int v1 = engineState[a2];
                a1 = engineState[v0];
                v1 += x;
                a2 ^= a1;
                x = v1 & 0xFF;
                output[i] = a2;
            }
        }

        public byte[] Encrypt(byte[] data)
        {
            // Set seed
            SetKey(workingKey, Hash(data));

            byte[] result = new byte[data.Length];
            Encrypt(data, 0, data.Length, result, 0);
            return result;
        }

        #endregion

        #endregion

    }
}
