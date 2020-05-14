using System;
using System.Collections.Generic;
using System.Text;

namespace UYA.Medius.Shared
{
    public class CipherContext
    {
        public ICipher MASConnectCipher = null;
        public ICipher MASResponseCipher = null;
        public ICipher SessionCipher = null;
        public ICipher Cipher94 = null;
    }
}
