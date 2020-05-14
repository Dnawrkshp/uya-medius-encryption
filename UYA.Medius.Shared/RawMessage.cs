using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace UYA.Medius.Shared
{


    public class RawMessage
    {
        public MessageId Id { get; protected set; } = MessageId.ID_00;
        public byte[] Data { get; protected set; } = null;

        public bool Signed { get; protected set; } = false;
        public MessageSignContext SignType { get; protected set; } = MessageSignContext.ID_00;
        public byte[] Hash { get; protected set; } = null;

        public byte[] Unsign(CipherContext context)
        {
            if (!Signed)
                return Data;

            switch (SignType)
            {
                case MessageSignContext.UNK_94: return Unsign(context.Cipher94);
                case MessageSignContext.Session: return Unsign(context.SessionCipher);
                case MessageSignContext.Authenticate:
                    {
                        if (Id == MessageId.ID_12)
                            return Unsign(context.MASConnectCipher);
                        else if (Id == MessageId.ID_13)
                            return Unsign(context.MASResponseCipher);

                        break;
                    }
            }

            throw new NotImplementedException($"Unable to decrype message ({Id}) with sign type {SignType}, hash:{BitConverter.ToString(Hash)}, data:{BitConverter.ToString(Data)}");
        }

        public byte[] Unsign(ICipher cipher)
        {
            if (cipher == null)
                throw new InvalidOperationException($"Unable to decrypt message ({Id}) with sign type {SignType}, hash:{BitConverter.ToString(Hash)}, data:{BitConverter.ToString(Data)} with a null cipher.");

            if (!Signed)
                return Data;

            if (cipher.Decrypt(Data, Hash, out var plain))
                return plain;

            throw new NotImplementedException($"Unable to decrypt message ({Id}) with sign type {SignType}, hash:{BitConverter.ToString(Hash)}, data:{BitConverter.ToString(Data)}");
        }

        public static List<RawMessage> FromString(string message)
        {
            List<RawMessage> messages = new List<RawMessage>();

            // Convert to byte array
            byte[] buffer = new byte[message.Length / 2];
            for (int i = 0; i < buffer.Length; ++i)
                buffer[i] = Convert.ToByte(message.Substring(i * 2, 2), 16);

            int index = 0;

            while (index < buffer.Length)
            {

                // Data
                byte id = buffer[index + 0];
                ushort len = (ushort)((buffer[index + 2] << 8) | buffer[index + 1]);
                byte[] hash = null;
                byte[] data = null;

                
                // Grab hash if signed
                // Otherwise just grab data
                if (id >= 0x80)
                {
                    hash = new byte[4];
                    Array.Copy(buffer, index + 3, hash, 0, 4);
                    data = new byte[len];
                    try
                    {
                        Array.Copy(buffer, index + 7, data, 0, data.Length);
                    }
                    catch (Exception e)
                    {

                    }
                    index += 3 + len + 4;
                }
                else
                {
                    data = new byte[len];
                    Array.Copy(buffer, index + 3, data, 0, data.Length);
                    index += 3 + len;
                }

                // Return encapsulated message
                messages.Add(new RawMessage()
                {
                    Id = (MessageId)(id & 0x7F),
                    Signed = id >= 0x80,
                    Hash = hash,
                    SignType = hash == null ? MessageSignContext.ID_00 : (MessageSignContext)(hash[3] >> 5),
                    Data = data
                });
            }

            return messages;
        }
    }

    public enum MessageSignContext : byte
    {
        ID_00,
        UNK_94,
        ID_02,
        Session,
        ID_04,
        ID_05,
        ID_06,
        Authenticate,
    }

    public enum MessageId : byte
    {
        ID_00,
        ID_01,
        ID_02,
        ID_03,
        ID_04,
        ID_05,
        ID_06,
        ID_07,
        ID_08,
        ID_09,
        ID_0a,
        ID_0b,
        ID_0c,
        ID_0d,
        ID_0e,
        ID_0f,
        ID_10,
        ID_11,
        ID_12,
        ID_13,
        ID_14,
        ID_15,
        ID_16,
        ID_17,
        ID_18,
        ID_19,
        ID_1a,
        ID_1b,
        ID_1c,
        ID_1d,
        ID_1e,
        ID_1f,
        ID_20,
        ID_21,
        ID_22,
        ID_23,
        ID_24,
        ID_25,
        ID_26,
        ID_27,
        ID_28,
        ID_29,
        ID_2a,
        ID_2b,
        ID_2c,
        ID_2d,
        ID_2e,
        ID_2f,
        ID_30,
        ID_31,
        ID_32,
        ID_33,
        ID_34,
        ID_35,
        ID_36,
        ID_37,
        ID_38,
        ID_39,
        ID_3a,
        ID_3b,
        ID_3c,
        ID_3d,
        ID_3e,
        ID_3f,
        ID_40,
        ID_41,
        ID_42,
        ID_43,
        ID_44,
        ID_45,
        ID_46,
        ID_47,
        ID_48,
        ID_49,
        ID_4a,
        ID_4b,
        ID_4c,
        ID_4d,
        ID_4e,
        ID_4f,
        ID_50,
        ID_51,
        ID_52,
        ID_53,
        ID_54,
        ID_55,
        ID_56,
        ID_57,
        ID_58,
        ID_59,
        ID_5a,
        ID_5b,
        ID_5c,
        ID_5d,
        ID_5e,
        ID_5f,
        ID_60,
        ID_61,
        ID_62,
        ID_63,
        ID_64,
        ID_65,
        ID_66,
        ID_67,
        ID_68,
        ID_69,
        ID_6a,
        ID_6b,
        ID_6c,
        ID_6d,
        ID_6e,
        ID_6f,
        ID_70,
        ID_71,
        ID_72,
        ID_73,
        ID_74,
        ID_75,
        ID_76,
        ID_77,
        ID_78,
        ID_79,
        ID_7a,
        ID_7b,
        ID_7c,
        ID_7d,
        ID_7e,
        ID_7f,
    }
}
