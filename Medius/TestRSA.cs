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
            BigInteger m_92 = new BigInteger("6B8F99EC1BAF06D2674284B5305EE6E38B1DE7331F2FBF31DE497228B7C52162F18DAE8913C40C43C0E890D14EEE16AD07C64FD9281D8B972D78BE78D1B290CE", 16);

            BigInteger n = new BigInteger("10315955513017997681600210131013411322695824559688299373570246338038100843097466504032586443986679280716603540690692615875074465586629501752500179100369237", 10);
            BigInteger e = new BigInteger("17", 10);
            BigInteger p = new BigInteger("101177020773116032450768434219907665711628442914109359705930212851485814671757", 10);
            BigInteger q = new BigInteger("101959470976625878182337603500729946859798449583099010462249380230433894289641", 10);
            BigInteger s = new BigInteger("1", 10);

            var q1 = q.Subtract(s);
            var p1 = p.Subtract(s);
            var pq = q1.Multiply(p1);
            BigInteger d = e.ModInverse(pq);

            RSA rsa = new RSA(
                // mod
                //new BigInteger("C4F75716EC835D2325689F91FF85ED9BFC3211DB9C164F41852E264E569D2802008054A0EF459E7E3EABB87FAE576E735434D1D124B30B11BD6DE09814860155", 16),
                n,

                // public exp
                e,

                // private exp
                //new BigInteger("4854567300243763614870687120476899445974505675147434999327174747312047455575182761195687859800492317495944895566174677168271650454805328075020357360662513", 10)
                d
                );

            Console.WriteLine("------------- 92 MESSAGE --------------");
            BigInteger signed = m_92.ModPow(e, n); // rsa.Encrypt(m_92);
            byte[] signedBytes = signed.ToByteArrayUnsigned();
            Console.WriteLine("Signed: " + Utils.BAToString(signedBytes));

            BigInteger unsigned = signed.ModPow(d, n);
            byte[] unsignedBytes = unsigned.ToByteArrayUnsigned();
            Console.WriteLine("Unsigned: " + Utils.BAToString(unsignedBytes));

            Console.WriteLine("DECRYPTION " + (unsigned.CompareTo(m_92) == 0 ? "WORKED!!!!!!!!!!!!!!!!!!!!" : "FAILED"));
        }

        public static void Handle93()
        {
            BigInteger c_93 = new BigInteger("AF9CBD1868A8C3CA4E547D4C0177FA92A7E475A83DB2F96CE1665BDB8048EE505968759EB8624345E1A56805E891344A2ADD26B2E32CA6DCD96E50414C8B7A1A", 16);
            BigInteger m_93 = new BigInteger("8694D579A31ADE7F3B37E08C520051BFC74D20F0D5F5A65C8D4488D4173538DBFA2ED807E48B9C326A884689DACE2347F0843DD96DF20D5E0BEF70D15C7E9360", 16);

            BigInteger c_94 = new BigInteger("403B472000686E07997AAA5260FCDF6B0B2860872A232FABEE396B6A664263813ACCBD1880A72BB78AD5697F5D114C9ACB4A971858D10A1F7D32DD27F3D06C73", 16);
            
            RSA rsa = new RSA(
                // mod
                new BigInteger("CE90B2D178BE782D978B1D28D94FC607AD16EE4ED190E8C0430CC41389AE8DF16221C5B7287249DE31BF2F1F33E71D8BE3E65E30B5844267D206AF1BEC998F6B", 16),

                // public exp
                new BigInteger("11", 16),

                // private exp
                new BigInteger("85A8EC2D3002C63B9E4AF4C014248F3224B47C14E1F45A5E4980BB1BB370F26DD8B80978FC2DCEC8B28563F1659A00B65C843D20732D3773E6AA95C37F9D5511", 16)
                );


            // 07CBF0876835BD72FE358D26ECDDB79F858A0CE1690DF49A19642D41B1B45A764A85586097AF6ABD65A1DAE4278E08848149F2EC6F2846FEAA039D4DE27D667F
            // 07CBF0876835BD72FE358D26ECDDB79F858A0CE1690DF49A19642D41B1B45A764A85586097AF6ABD652C9D892C92E7BEEB2187B0E09D48A2B4F89C13EE21B5CB

            Console.WriteLine("------------- 93 MESSAGE --------------");

            BigInteger unsigned = rsa.Decrypt(c_94);
            byte[] unsignedBytes = unsigned.ToByteArrayUnsigned();
            Console.WriteLine("Unsigned: " + Utils.BAToString(unsignedBytes));

            Console.WriteLine("DECRYPTION " + (unsigned.CompareTo(m_93) == 0 ? "WORKED!!!!!!!!!!!!!!!!!!!!" : "FAILED"));
        }

    }
}
