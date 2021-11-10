using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Text;

namespace Medius.Crypto
{
    public class PS3_RSA : RSA
    {
        public PS3_RSA(BigInteger n, BigInteger e, BigInteger d) : base(n, e, d)
        {

        }

        public override void Hash(byte[] input, out byte[] hash)
        {
            hash = PS3_RC.Hash(input, Context);
        }
    }
}
