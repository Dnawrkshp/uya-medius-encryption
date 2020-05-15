using CommandLine;
using Medius.Crypto;
using Medius.Shared.Message;
using Org.BouncyCastle.Bcpg;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection.Metadata;
using System.Text;

namespace MediusTool.Operations
{
    [Verb("decrypt-pcap", HelpText = "Decrypt a pcap file")]
    class DecryptPcapOp
    {
        [Option('i', "input path", Required = true, HelpText = "Path to pcap/pcapng file.")]
        public string Input { get; set; }

        [Option('o', "output path", Required = false, HelpText = "Path to output pcap/pcapng file.")]
        public string Output { get; set; }

        [Option('v', "version", Required = true, Default = Versions.PS2_UYA, HelpText = "PS2_UYA|PS3")]
        public Versions Version { get; set; }

        private IEnumerable<ICipher> _asymCiphers = null;

        private List<DecryptPcapMessage> _packets = new List<DecryptPcapMessage>();
        public int Run()
        {
            // populate collection of ciphers
            switch (Version)
            {
                case Versions.PS2_UYA: { _asymCiphers = Program.AsymmetricKeys.Select(x => x as ICipher); break; }
                case Versions.PS3: { _asymCiphers = Program.PS3_AsymmetricKeys.Select(x => x as ICipher); break; }
            }

            Program.CreateBruteforceCiphers(Version);

            var device = new CaptureFileReaderDevice(Input);
            device.OnPacketArrival += device_OnPacketArrival;

            // Open the device for capturing
            device.Open();

            // 
            device.Capture();

            foreach (var msg in _packets)
            {
                Console.WriteLine(msg.Message);
                HandlePacket(msg.Buffer.ToArray(), _asymCiphers);
                Console.WriteLine();
            }

            return 0;
        }

        void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            try
            {
                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

                if (packet is EthernetPacket)
                {
                    var eth = ((EthernetPacket)packet);

                    var ip = packet.Extract<IPPacket>();
                    if (ip != null)
                    {
                        var tcp = packet.Extract<TcpPacket>();
                        if (tcp != null && (tcp.DestinationPort == 10075 || tcp.DestinationPort == 10078 || tcp.SourcePort == 10078 || tcp.SourcePort == 10075))
                        {
                            if (tcp.PayloadData != null && tcp.PayloadData.Length > 0)
                            {
                                DecryptPcapMessage packetMessage = null;

                                // Check to see if fragment
                                var lastFromSender = _packets.LastOrDefault(x => x.SourceAddress.Equals(ip.SourceAddress));
                                if (lastFromSender != null && lastFromSender.Ack == tcp.AcknowledgmentNumber)
                                {
                                    lastFromSender.Buffer.AddRange(tcp.PayloadData);
                                }
                                else
                                {
                                    packetMessage = new DecryptPcapMessage()
                                    {
                                        SourceAddress = ip.SourceAddress,
                                        Ack = tcp.AcknowledgmentNumber,
                                        Message = $"PACKET: {ip.SourceAddress}:{tcp.SourcePort} => {ip.DestinationAddress}:{tcp.DestinationPort}",
                                        Buffer = new List<byte>(tcp.PayloadData)
                                    };
                                    _packets.Add(packetMessage);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                Console.WriteLine();
            }
        }

        void HandlePacket(byte[] msgBuffer, IEnumerable<ICipher> asymCiphers)
        {
            try
            {
                var messages = BaseMessage.InstantiateBruteforce(msgBuffer, (id, context) =>
                {
                    switch (context)
                    {
                        case CipherContext.RSA_AUTH: return asymCiphers;
                        default: return Program.SymmetricCiphers[context];
                    }

                });


                foreach (var msg in messages)
                {
                    var rawMessage = msg as RawMessage;

                    // Parse
                    switch (msg.Id)
                    {
                        // CLIENT AUTH
                        case MessageIds.ID_12:
                            {

                                break;
                            }
                        // SESSION KEY
                        case MessageIds.ID_13:
                            {
                                AddNewSymmetric(rawMessage.Contents);
                                break;
                            }
                        case MessageIds.ID_14:
                            {
                                AddNewSymmetric(rawMessage.Contents);
                                break;
                            }
                        default:
                            {

                                break;
                            }
                    }

                    Console.WriteLine($"[SUCCESS] ID:{msg.Id} PLAINTEXT: ");
                    Utils.FancyPrintBA((msg as RawMessage).Contents);
                    Console.WriteLine();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine();
            }
        }

        void AddNewSymmetric(byte[] key)
        {
            List<ICipher> ciphers = new List<ICipher>();

            for (CipherContext context = 0; context < CipherContext.RSA_AUTH; ++context)
            {
                switch (Version)
                {
                    case Versions.PS2_UYA:
                        {
                            ciphers.Add(new PS2_UYA_RC4(key, context));
                            break;
                        }
                    case Versions.PS3:
                        {
                            ciphers.Add(new PS3_RC(key, context));
                            break;
                        }
                }
            }

            Program.AddSymmetricCiphers(ciphers);
        }
    }

    class DecryptPcapMessage
    {
        public IPAddress SourceAddress;
        public string Message;
        public uint Ack;
        public List<byte> Buffer;
    }
}
