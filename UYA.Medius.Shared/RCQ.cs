using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace UYA.Medius.Shared
{
    public class RCQ : ICipher
    {
        private byte[] _key = null;
        private MessageSignContext _context = MessageSignContext.ID_00;

        public RCQ(byte[] key, MessageSignContext context)
        {
            _context = context;
            SetKey(key);
        }

        public void SetKey(byte[] key)
        {
            _key = key;
        }

        public bool Encrypt(byte[] input, out byte[] cipher, out byte[] hash)
        {
            hash = null;
            cipher = null;
            if (_key == null)
                return false;

            hash = Utils.HashPS3(input, _context, false);

            // IV
            byte[] iv = new byte[0x10];
            uint[] seed = new uint[4];
            Array.Copy(_key, 0, iv, 0, 0x10);
            Utils.HashPS3_Flip(iv);

            for (int i = 0; i < 4; ++i)
                seed[i] = BitConverter.ToUInt32(iv, i * 4);
            var keyHash = Utils.HashPS3_Seeded(hash, ref seed);

            for (int i = 0; i < 4; ++i)
            {
                var b = BitConverter.GetBytes(seed[i]);
                Array.Copy(b, 0, iv, i * 4, 4);
            }

            Utils.HashPS3_Seeded(iv, ref seed);
            Utils.HashPS3_Seeded(input, ref seed, true);
            return true;
        }

        public bool Decrypt(byte[] input, byte[] hash, out byte[] plain)
        {
            plain = null;
            if (_key == null)
                return false;

            plain = new byte[input.Length];
            Array.Copy(input, 0, plain, 0, plain.Length);

            // IV
            byte[] iv = new byte[0x10];
            uint[] seed = new uint[4];
            Array.Copy(_key, 0, iv, 0, 0x10);
            Utils.HashPS3_Flip(iv);

            for (int i = 0; i < 4; ++i)
                seed[i] = BitConverter.ToUInt32(iv, i * 4);
            var keyHash = Utils.HashPS3_Seeded(hash, ref seed);

            for (int i = 0; i < 4; ++i)
            {
                var b = BitConverter.GetBytes(seed[i]);
                Array.Copy(b, 0, iv, i * 4, 4);
            }

            Utils.HashPS3_Seeded(iv, ref seed);
            Utils.HashPS3_Seeded(plain, ref seed, true);
            return true;
        }
    }
}
