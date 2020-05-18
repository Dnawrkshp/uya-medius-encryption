using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Medius.Crypto
{
    /// <summary>
    /// UYA's custom RC4 implementation,
    /// based off https://github.com/bcgit/bc-csharp/blob/f18a2dbbc2c1b4277e24a2e51f09cac02eedf1f5/crypto/src/crypto/engines/RC4Engine.cs
    /// </summary>
    public class PS2_UYA_RC4 : ICipher
    {
        private readonly static int STATE_LENGTH = 256;

        /// <summary>
        /// Cipher context.
        /// </summary>
        public CipherContext Context { get; protected set; } = CipherContext.ID_00;

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
        public PS2_UYA_RC4(byte[] key, CipherContext context)
        {
            Context = context;
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
                y = (y + 5) & 0xFF;

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

        public bool Decrypt(byte[] data, byte[] hash, out byte[] plain)
        {
            plain = new byte[data.Length];

            // Check if empty hash
            // If hash is 0, the data is already in plaintext
            if (hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && (hash[3] & 0x1F) == 0)
            {
                Array.Copy(data, 0, plain, 0, data.Length);
                return true;
            }

            // Set seed
            SetKey(workingKey, hash);

            Decrypt(data, 0, data.Length, plain, 0);
            Hash(plain, out var checkHash);
            return hash.SequenceEqual(checkHash);
        }

        #endregion

        #region Encrypt

        private void Encrypt(
                byte[] input,
                int inOff,
                int length,
                byte[] output,
                int outOff)
        {

            for (int i = 0; i < length; ++i)
            {
                x = (x + 5) & 0xff;
                y = (y + engineState[x]) & 0xff;

                // Swap
                byte temp = engineState[x];
                engineState[x] = engineState[y];
                engineState[y] = temp;

                // Xor
                output[i + outOff] = (byte)(
                    input[i + inOff]
                    ^
                    engineState[(engineState[x] + engineState[y]) & 0xff]
                    );

                // 
                y = (engineState[input[i + inOff]] + y) & 0xff;
            }
        }

        public bool Encrypt(byte[] data, out byte[] cipher, out byte[] hash)
        {
            // Set seed
            hash = SHA1.Hash(data, Context);
            SetKey(workingKey, hash);

            cipher = new byte[data.Length];
            Encrypt(data, 0, data.Length, cipher, 0);
            return true;
        }

        #endregion

        #region Hash

        public void Hash(byte[] input, out byte[] hash)
        {
            hash = SHA1.Hash(input, Context);
        }

        #endregion

        #region Comparison

        public override bool Equals(object obj)
        {
            if (obj is PS2_UYA_RC4 rc)
                return rc.Equals(this);

            return base.Equals(obj);
        }

        public bool Equals(PS2_UYA_RC4 b)
        {
            return b.Context == this.Context && (b.workingKey?.SequenceEqual(this.workingKey) ?? false);
        }

        #endregion

        public override string ToString()
        {
            return $"PS2_UYA_RC4({Context}, {BitConverter.ToString(workingKey).Replace("-", "")})";
        }

    }
}
