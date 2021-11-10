using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Medius.Shared.Message
{
    public class RawMessage : BaseMessage
    {
        protected MessageIds _id = MessageIds.ID_00;
        public override MessageIds Id => _id;

        public byte[] Contents { get; protected set; }

        public RawMessage()
        {

        }

        public RawMessage(MessageIds id)
        {
            _id = id;
        }
        public override void Deserialize(BinaryReader reader)
        {
            Contents = new byte[reader.BaseStream.Length - reader.BaseStream.Position];
            Contents = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
        }

        protected override void Serialize(BinaryWriter writer)
        {
            writer.Write(Contents);
        }
    }
}
