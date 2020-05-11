using System;
using System.Collections.Generic;
using System.Text;

namespace UYA.Medius.Shared
{
    public class CipherContext
    {
        public RSA MASConnectCipher = null;
        public RSA MASResponseCipher = null;
        public RC4 SessionCipher = null;
        public RC4 Cipher94 = null;
    }
}
