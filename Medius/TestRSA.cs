using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Text;
using UYA.Medius.Shared;

namespace Medius
{
    class TestRSA
    {

        public static void Handle92()
        {
            BigInteger m_92 = new BigInteger("CE90B2D178BE782D978B1D28D94FC607AD16EE4ED190E8C0430CC41389AE8DF16221C5B7287249DE31BF2F1F33E71D8BE3E65E30B5844267D206AF1BEC998F6B", 16);
            
            RSA rsa = new RSA(
                // mod
                new BigInteger("C4F75716EC835D2325689F91FF85ED9BFC3211DB9C164F41852E264E569D2802008054A0EF459E7E3EABB87FAE576E735434D1D124B30B11BD6DE09814860155", 16),

                // public exp
                new BigInteger("11", 16),

                // private exp
                new BigInteger("29BC", 16)
                );


            Console.WriteLine("------------- 92 MESSAGE --------------");
            BigInteger signed = rsa.Encrypt(m_92);
            byte[] signedBytes = signed.ToByteArrayUnsigned();
            Console.WriteLine("Signed: " + Utils.BAToString(signedBytes));

            BigInteger unsigned = rsa.Decrypt(signed);
            byte[] unsignedBytes = unsigned.ToByteArrayUnsigned();
            Console.WriteLine("Unsigned: " + Utils.BAToString(unsignedBytes));

            Console.WriteLine("DECRYPTION " + (unsigned.CompareTo(m_92) == 0 ? "WORKED!!!!!!!!!!!!!!!!!!!!" : "FAILED"));
        }

        public static void Handle93()
        {
            BigInteger c_93 = new BigInteger("AF9CBD1868A8C3CA4E547D4C0177FA92A7E475A83DB2F96CE1665BDB8048EE505968759EB8624345E1A56805E891344A2ADD26B2E32CA6DCD96E50414C8B7A1A", 16);
            BigInteger m_93 = new BigInteger("8694D579A31ADE7F3B37E08C520051BFC74D20F0D5F5A65C8D4488D4173538DBFA2ED807E48B9C326A884689DACE2347F0843DD96DF20D5E0BEF70D15C7E9360", 16);

            RSA rsa = new RSA(
                // mod
                new BigInteger("CE90B2D178BE782D978B1D28D94FC607AD16EE4ED190E8C0430CC41389AE8DF16221C5B7287249DE31BF2F1F33E71D8BE3E65E30B5844267D206AF1BEC998F6B", 16),

                // public exp
                new BigInteger("00", 16),

                // private exp
                new BigInteger("85A8EC2D3002C63B9E4AF4C014248F3224B47C14E1F45A5E4980BB1BB370F26DD8B80978FC2DCEC8B28563F1659A00B65C843D20732D3773E6AA95C37F9D5511", 16)
                );


            Console.WriteLine("------------- 93 MESSAGE --------------");

            BigInteger unsigned = rsa.Decrypt(c_93);
            byte[] unsignedBytes = unsigned.ToByteArrayUnsigned();
            Console.WriteLine("Unsigned: " + Utils.BAToString(unsignedBytes));

            Console.WriteLine("DECRYPTION " + (unsigned.CompareTo(m_93) == 0 ? "WORKED!!!!!!!!!!!!!!!!!!!!" : "FAILED"));
        }

    }
}
