using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MediusTool
{
    static class Utils
    {
        public static byte[] BAFromString(string str)
        {
            byte[] buffer = new byte[str.Length / 2];

            for (int i = 0; i < buffer.Length; ++i)
                buffer[i] = byte.Parse(str.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);

            return buffer;
        }

        public static byte[] BAFromStringFlipped(string str)
        {
            byte[] buffer = new byte[str.Length / 2];

            for (int i = 0; i < buffer.Length; ++i)
                buffer[i] = byte.Parse(str.Substring((buffer.Length - i - 1) * 2, 2), System.Globalization.NumberStyles.HexNumber);

            return buffer;
        }

        public static string BAToString(byte[] buffer)
        {
            if (buffer == null)
                return "";

            string str = "";
            for (int i = 0; i < buffer.Length; ++i)
                str += buffer[i].ToString("X2");

            return str;
        }

        public static void FancyPrintBA(byte[] buffer)
        {
            string str = "";
            for (int i = 0; i < buffer.Length; ++i)
            {
                char c = (char)buffer[i];
                Console.Write(buffer[i].ToString("X2") + " ");
                str += char.IsControl(c) ? '.' : c;
            }

            Console.WriteLine();
            Console.WriteLine(str);
        }

        public static byte[] FlipEndianness(byte[] buffer, int groupSize)
        {
            if (groupSize <= 1)
                return buffer;

            var newBuf = buffer.ToArray();
            for (int i = 0; i < buffer.Length; i += groupSize)
            {
                for (int j = 0; j < (groupSize-1); ++j)
                    newBuf[i + j] = buffer[i + j + 1];
                newBuf[i + groupSize - 1] = buffer[i];
            }

            return newBuf;
        }
    }
}
