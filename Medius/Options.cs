using CommandLine;
using CommandLine.Text;
using System;
using System.Collections.Generic;
using System.Text;

namespace Medius
{
    [Verb("decrypt", HelpText = "Decrypt packet")]
    class DecryptOptions
    {
        [Option('k', "key", Required = false, HelpText = "Key as a hexstring (64 bytes).")]
        public string Key { get; set; }

        [Option('p', "packet", Required = true, HelpText = "Packet as a hexstring.")]
        public string Packet { get; set; }
    }

    [Verb("encrypt", HelpText = "Encrypt message")]
    class EncryptOptions
    {
        [Option('k', "key", Required = false, HelpText = "Key as a hexstring (64 bytes).")]
        public string Key { get; set; }

        [Option('m', "message", Required = true, HelpText = "Message as hexstring.")]
        public string Message { get; set; }
    }

    [Verb("decrypt-stream", HelpText = "Decrypt a collection of medius messages")]
    class DecryptStreamOptions
    {
        [Option('f', "filepath", Required = true, HelpText = "Path to file containing collection of medius messages.")]
        public string Filepath { get; set; }
    }
}
