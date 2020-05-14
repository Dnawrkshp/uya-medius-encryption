using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace UYA.Medius.Shared
{
    [JsonConverter(typeof(RSAConverter))]
    public class RSA : ICipher
    {
        public string Comment = "";
        public BigInteger n => _n;
        public BigInteger e => _e;
        public BigInteger d => _d;

        BigInteger _n;
        BigInteger _e;
        BigInteger _d;

        public RSA(BigInteger n, BigInteger e, BigInteger d)
        {
            _n = n;
            _e = e;
            _d = d;
        }



        private BigInteger Encrypt(BigInteger m)
        {
            return m.ModPow(_e, _n);
        }

        private BigInteger Decrypt(BigInteger c)
        {
            return c.ModPow(_d, _n);
        }

        public bool Decrypt(byte[] input, byte[] hash, out byte[] plain)
        {
            bool match = false;
            var plainBigInt = Decrypt(input.ToBigInteger());
            
            plain = plainBigInt.ToBA();
            match = Utils.HashPS3(plain, MessageSignContext.Authenticate).SequenceEqual(hash);
            if (match)
                return true;

            // Handle case where message > n
            plainBigInt = plainBigInt.Add(_n);
            plain = plainBigInt.ToBA();
            return Utils.HashPS3(plain, MessageSignContext.Authenticate).SequenceEqual(hash);
        }

        public bool Encrypt(byte[] input, out byte[] cipher, out byte[] hash)
        {
            hash = Utils.HashPS3(input, MessageSignContext.Authenticate);
            cipher = Encrypt(input.ToBigInteger()).ToBA();
            return true;
        }
    }

    public class RSAConverter : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            RSA rsa = (RSA)value;

            writer.WriteStartObject();
            writer.WritePropertyName("comment");
            serializer.Serialize(writer, rsa.Comment.ToString());
            writer.WritePropertyName("n");
            serializer.Serialize(writer, rsa.n.ToString());
            writer.WritePropertyName("e");
            serializer.Serialize(writer, rsa.e.ToString());
            writer.WritePropertyName("d");
            serializer.Serialize(writer, rsa.d.ToString());
            writer.WriteEndObject();
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            JObject jsonObject = JObject.Load(reader);

            var sN = (string)jsonObject["n"];
            var sE = (string)jsonObject["e"];
            var sD = (string)jsonObject["d"];
            return new RSA(new BigInteger(sN, 10), new BigInteger(sE, 10), new BigInteger(sD, 10)) { Comment = (string)jsonObject["comment"] };
        }

        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(RSA);
        }
    }
}
