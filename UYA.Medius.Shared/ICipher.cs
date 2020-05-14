using System;
using System.Collections.Generic;
using System.Text;

namespace UYA.Medius.Shared
{
    public interface ICipher
    {
        bool Decrypt(byte[] input, byte[] hash, out byte[] plain);
        bool Encrypt(byte[] input, out byte[] cipher, out byte[] hash);
    }
}
