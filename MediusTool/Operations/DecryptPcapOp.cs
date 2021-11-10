using CommandLine;
using Medius.Crypto;
using Medius.Shared.Message;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc7748;
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
        ushort[] ports = new ushort[]
        {
                2000,
                2001,
               // 10070,
                10071,
                10072,
                10073,
                10074,
                10075,
                10076,
                10077,
                10078,
                10079,
                10080,
                10090,
                10091,
                10092,
                10093,
                10094,
                10095,
                10096,
                10097,
                10098,
                10099,
        };


        [Option('i', "input path", Required = true, HelpText = "Path to pcap/pcapng file.")]
        public string Input { get; set; }

        [Option('o', "output path", Required = false, HelpText = "Path to output pcap/pcapng file.")]
        public string Output { get; set; }

        [Option('v', "version", Required = true, Default = Versions.PS2_UYA, HelpText = "PS2_UYA|PS3")]
        public Versions Version { get; set; }

        private IEnumerable<ICipher> _asymCiphers = null;

        private List<DecryptPcapMessage> _packets = new List<DecryptPcapMessage>();

        private int frame = 0;
        private DateTime? firstDate = null;

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
            // packet index
            ++frame;

            try
            {
                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                if (firstDate == null)
                    firstDate = e.Packet.Timeval.Date;


                var timeVal = (e.Packet.Timeval.Date - firstDate.Value).TotalSeconds;

                if (packet is EthernetPacket)
                {
                    var eth = ((EthernetPacket)packet);

                    var ip = packet.Extract<IPPacket>();
                    if (ip != null)
                    {
                        TryPacket(packet, ip, timeVal);
                    }
                }
                else
                {
                    var ip = packet.Extract<IPPacket>();
                    if (ip != null)
                    {
                        TryPacket(packet, ip, timeVal);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                Console.WriteLine();
            }
        }

        void TryPacket(PacketDotNet.Packet packet, IPPacket ip, double time)
        {
            DecryptPcapMessage packetMessage = null;

            var tcp = packet.Extract<TcpPacket>();
            if (tcp != null && (ports.Contains(tcp.DestinationPort) || ports.Contains(tcp.SourcePort)))
            {
                if (tcp.PayloadData != null && tcp.PayloadData.Length > 0)
                {
                    int i = 0;
                    while (i < tcp.PayloadData.Length)
                    {
                        // Check to see if fragment
                        var lastFromSender = _packets.LastOrDefault(x => x.SourceAddress.Equals(ip.SourceAddress) && x.Port.Equals(tcp.SourcePort));
                        if (lastFromSender != null && !lastFromSender.IsFull)
                        {
                            while (!lastFromSender.IsFull && i < tcp.PayloadData.Length)
                                lastFromSender.Buffer.Add(tcp.PayloadData[i++]);
                        }
                        else
                        {
                            byte id = tcp.PayloadData[i + 0];
                            uint len = (uint)(tcp.PayloadData[i + 2] << 8) | (uint)tcp.PayloadData[i + 1]; // + (uint)(id >= 0x80 ? 4 : 0);
                            if (id >= 0x80 && len > 0)
                                len += 4;

                            packetMessage = new DecryptPcapMessage()
                            {
                                SourceAddress = ip.SourceAddress,
                                Port = tcp.SourcePort,
                                Len = (uint)(len + 3),
                                Message = $"{frame} [+{time}] TCP PACKET: {ip.SourceAddress}:{tcp.SourcePort} => {ip.DestinationAddress}:{tcp.DestinationPort}",
                                Time = time,
                                Buffer = new List<byte>()
                            };

                            while (!packetMessage.IsFull && i < tcp.PayloadData.Length)
                                packetMessage.Buffer.Add(tcp.PayloadData[i++]);

                            _packets.Add(packetMessage);
                        }
                    }
                }
            }

            var udp = packet.Extract<UdpPacket>();
            // udp = null;
            if (udp != null && ((udp.DestinationPort >= 50000 && udp.DestinationPort < 50100) || (udp.SourcePort >= 50000 && udp.SourcePort < 50100) || ports.Contains(udp.DestinationPort) || ports.Contains(udp.SourcePort)))
            {
                if (udp.PayloadData != null && udp.PayloadData.Length > 0)
                {
                    int i = 0;
                    while (i < udp.PayloadData.Length)
                    {
                        // Check to see if fragment
                        var lastFromSender = _packets.LastOrDefault(x => x.SourceAddress.Equals(ip.SourceAddress) && x.Port.Equals(udp.SourcePort));
                        if (lastFromSender != null && !lastFromSender.IsFull)
                        {
                            while (!lastFromSender.IsFull && i < udp.PayloadData.Length)
                                lastFromSender.Buffer.Add(udp.PayloadData[i++]);
                        }
                        else
                        {
                            byte id = udp.PayloadData[i + 0];
                            uint len = (uint)(udp.PayloadData[i + 2] << 8) | (uint)udp.PayloadData[i + 1]; // + (uint)(id >= 0x80 ? 4 : 0);
                            if (id >= 0x80 && len > 0)
                                len += 4;

                            packetMessage = new DecryptPcapMessage()
                            {
                                SourceAddress = ip.SourceAddress,
                                Port = udp.SourcePort,
                                Len = (uint)(len + 3),
                                Message = $"{frame} [+{time}] UDP PACKET: {ip.SourceAddress}:{udp.SourcePort} => {ip.DestinationAddress}:{udp.DestinationPort}",
                                Time = time,
                                Buffer = new List<byte>()
                            };

                            while (!packetMessage.IsFull && i < udp.PayloadData.Length)
                                packetMessage.Buffer.Add(udp.PayloadData[i++]);

                            _packets.Add(packetMessage);
                        }
                    }
                }
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
                                var key = rawMessage.Contents.Reverse().ToArray();
                                var keyInt = new BigInteger(1, key);
                                Console.WriteLine("N: " + keyInt.ToString());
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
                        case MessageIds.ID_0a:
                            {

                                if (rawMessage.Contents.Length == 0xC6 && rawMessage.Contents[0] == 0x01 && rawMessage.Contents[1] == 0x08 && rawMessage.Contents[2] == 0x31)
                                {
                                    byte[] key = new byte[64];
                                    Array.Copy(rawMessage.Contents, 0x62, key, 0, key.Length);
                                    //AddNewSymmetric(key);
                                }

                                break;
                            }
                        default:
                            {

                                break;
                            }
                    }

                    Console.WriteLine($"[SUCCESS] ID:{msg.Id} LEN:0x{(msg as RawMessage)?.Contents?.Length ?? 0:X2} PLAINTEXT: ");
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
        public int Port;
        public string Message;
        public uint Len;
        public List<byte> Buffer;
        public double Time;

        public bool IsFull => Buffer.Count >= Len;
    }
}
