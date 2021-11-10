using Medius.Crypto;
using System;
using System.Collections.Generic;
using System.IO;

namespace Medius.Shared.Message
{
    public abstract class BaseMessage
    {
        /// <summary>
        /// Message id.
        /// </summary>
        public abstract MessageIds Id { get; }

        public BaseMessage()
        {

        }

        #region Serialization

        /// <summary>
        /// Deserializes the message from plaintext.
        /// </summary>
        /// <param name="reader"></param>
        public abstract void Deserialize(BinaryReader reader);
        
        /// <summary>
        /// Serializes the message and encrypts it with a given cipher.
        /// </summary>
        public void Serialize(ICipher cipher, out byte[] result, out byte[] hash)
        {
            // serialize
            Serialize(out var plain);

            // encrypt
            if (!cipher.Encrypt(plain, out result, out hash))
                throw new InvalidOperationException($"Unable to encrypt {Id} message: {BitConverter.ToString(plain).Replace("-", "")}");
        }

        /// <summary>
        /// Serializes the message.
        /// </summary>
        public void Serialize(out byte[] result)
        {
            var buffer = new byte[1024 * 4];
            int length = 0;

            // 
            using (MemoryStream stream = new MemoryStream(buffer, true))
            {
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    Serialize(writer);
                    length = (int)writer.BaseStream.Position;
                }
            }

            result = new byte[length];
            Array.Copy(buffer, 0, result, 0, length);
        }

        /// <summary>
        /// Serialize contents of the message.
        /// </summary>
        protected abstract void Serialize(BinaryWriter writer);

        #endregion

        #region Dynamic Instantiation

        private static Dictionary<MessageIds, Type> _messageClassById = new Dictionary<MessageIds, Type>();
        public static void RegisterMessage(MessageIds id, Type type)
        {
            // Set or overwrite.
            if (!_messageClassById.ContainsKey(id))
                _messageClassById.Add(id, type);
            else
                _messageClassById[id] = type;
        }

        public static List<BaseMessage> InstantiateBruteforce(byte[] messageBuffer, Func<MessageIds, CipherContext, IEnumerable<ICipher>> getCiphersCallback = null)
        {
            List<BaseMessage> msgs = new List<BaseMessage>();
            BaseMessage msg = null;

            // 
            using (MemoryStream stream = new MemoryStream(messageBuffer))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    while (reader.BaseStream.CanRead && reader.BaseStream.Position < reader.BaseStream.Length)
                    {
                        // Reset
                        msg = null;

                        // Parse header
                        byte rawId = reader.ReadByte();
                        MessageIds id = (MessageIds)(rawId & 0x7F);
                        bool encrypted = rawId >= 0x80;
                        ushort len = reader.ReadUInt16();

                        // Get class
                        if (!_messageClassById.TryGetValue(id, out var classType))
                            classType = null;

                        // Decrypt
                        if (len > 0 && encrypted)
                        {
                            byte[] hash = reader.ReadBytes(4);
                            byte[] ex = null;
                            if (id == MessageIds.ID_03)
                                ex = reader.ReadBytes(2);
                            CipherContext context = (CipherContext)(hash[3] >> 5);
                            var ciphers = getCiphersCallback(id, context);
                            byte[] cipherText = reader.ReadBytes(len);

                            foreach (var cipher in ciphers)
                            {
                                if (cipher.Decrypt(cipherText, hash, out var plain))
                                {
                                    msg = Instantiate(classType, id, plain);
                                    break;
                                }
                            }

                            if (msg == null)
                                Console.WriteLine($"Unable to decrypt {id}: {BitConverter.ToString(messageBuffer).Replace("-", "")}\n\n");
                        }
                        else
                        {
                            msg = Instantiate(classType, id, reader.ReadBytes(len));
                        }

                        if (msg != null)
                            msgs.Add(msg);
                    }
                }
            }

            return msgs;
        }

        public static List<BaseMessage> Instantiate(byte[] messageBuffer, Func<MessageIds, CipherContext, ICipher> getCipherCallback = null)
        {
            List<BaseMessage> msgs = new List<BaseMessage>();
            BaseMessage msg = null;

            // 
            using (MemoryStream stream = new MemoryStream(messageBuffer))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    while (reader.BaseStream.CanRead)
                    {
                        // Reset
                        msg = null;

                        // Parse header
                        byte rawId = reader.ReadByte();
                        MessageIds id = (MessageIds)(rawId & 0x7F);
                        bool encrypted = rawId >= 0x80;
                        ushort len = reader.ReadUInt16();

                        // Get class
                        if (!_messageClassById.TryGetValue(id, out var classType))
                            classType = null;

                        // Decrypt
                        if (encrypted)
                        {
                            byte[] hash = reader.ReadBytes(4);
                            CipherContext context = (CipherContext)(hash[3] >> 5);
                            var cipher = getCipherCallback(id, context);

                            if (cipher.Decrypt(reader.ReadBytes(len), hash, out var plain))
                                msg = Instantiate(classType, id, plain);
                            else
                                throw new InvalidOperationException($"Unable to decrypt {id}: {BitConverter.ToString(messageBuffer).Replace("-", "")}\n\n");
                        }
                        else
                        {
                            msg = Instantiate(classType, id, reader.ReadBytes(len));
                        }

                        if (msg != null)
                            msgs.Add(msg);
                    }
                }
            }

            return msgs;
        }

        private static BaseMessage Instantiate(Type classType, MessageIds id, byte[] plain)
        {
            BaseMessage msg = null;

            // 
            using (MemoryStream stream = new MemoryStream(plain))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    if (classType == null)
                        msg = new RawMessage(id);
                    else
                        msg = (BaseMessage)Activator.CreateInstance(classType);

                    msg.Deserialize(reader);
                }
            }

            return msg;
        }

        #endregion

    }
}
