using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Text;

namespace UYA.Medius.Shared
{
    public class RSA
    {
        BigInteger _n;
        BigInteger _e;
        BigInteger _d;

        public RSA(BigInteger n, BigInteger e, BigInteger d)
        {
            _n = n;
            _e = e;
            _d = d;
        }

        public BigInteger Encrypt(BigInteger m)
        {
            return m.ModPow(_e, _n);
        }

        public BigInteger Decrypt(BigInteger c)
        {
            return c.ModPow(_d, _n);
        }

    }
}
