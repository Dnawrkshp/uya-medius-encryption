using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Linq;

namespace UYA.Medius.Shared
{
    /// <summary>
    /// UYA's custom RC4 implementation,
    /// based off https://github.com/bcgit/bc-csharp/blob/f18a2dbbc2c1b4277e24a2e51f09cac02eedf1f5/crypto/src/crypto/engines/RC4Engine.cs
    /// </summary>
    public class RC4 : ICipher
    {
        private readonly static int STATE_LENGTH = 256;

        public MessageSignContext EncryptionType { get; protected set; } = MessageSignContext.ID_00;

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
        public RC4(byte[] key, MessageSignContext encryptionType)
        {
            EncryptionType = encryptionType;
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
            // Set seed
            SetKey(workingKey, hash);

            plain = new byte[data.Length];
            Decrypt(data, 0, data.Length, plain, 0);
            return true;
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
            hash = Utils.Hash(data, EncryptionType);
            SetKey(workingKey, hash);

            cipher = new byte[data.Length];
            Encrypt(data, 0, data.Length, cipher, 0);
            return true;
        }

        #endregion
        
    }
}
