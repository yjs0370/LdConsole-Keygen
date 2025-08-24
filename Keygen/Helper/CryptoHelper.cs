using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Keygen
{
    internal static partial class CryptoHelper
    {
        [DllImport(@"\GetKey\ArLib.dll", SetLastError = true)]
        private static extern int DllGetComputerCode(StringBuilder stringBuilder);

        [DllImport(@"\GetKey\ArLib.dll", SetLastError = true)]
        private static extern int DllEncryptString_Des(StringBuilder enc, string dec, string str = "Ld_Tq_Se");

        [DllImport(@"\GetKey\ArLib.dll", SetLastError = true)]
        private static extern int MD5(string a1, StringBuilder a2);

        public static event EventHandler GetMd5Progress;

        public static Tuple<byte[], byte[]> GetDecryptFileByte()
        {
            byte[] byteArray = CryptoHelper.GetBaseIrsBytes();
            byte[] md5 = byteArray.Skip(15).Take(32).ToArray();
            int totalLength = byteArray.Length;
            int startIndex = 52;
            int blockSize = 512;

            List<byte> decryptedBytes = new List<byte>(totalLength - startIndex);

            while (startIndex < totalLength)
            {
                int currentBlockSize = Math.Min(blockSize, totalLength - startIndex);
                byte[] block = new byte[currentBlockSize];

                Array.Copy(byteArray, startIndex, block, 0, currentBlockSize);
                CryptoHelper.DecryptAndEncrypt(block, md5, currentBlockSize);

                decryptedBytes.AddRange(block);
                startIndex += currentBlockSize;
            }

            byte[] header = byteArray.Take(52).ToArray();
            byte[] decryptedData = decryptedBytes.ToArray();

            return Tuple.Create(header, decryptedData);
        }

        public static byte[] GetEncryptFileByte(byte[] head, byte[] body, string computerCode, string md5, string user)
        {
            CryptoHelper.UpdateLicenseInfo(head, body, computerCode, md5, user);

            int totalLength = body.Length;
            int startIndex = 0;
            int blockSize = 512;

            List<byte> encryptedBody = new List<byte>(totalLength);

            byte[] md5Bytes = Encoding.ASCII.GetBytes(md5);

            while (startIndex < totalLength)
            {
                int currentBlockSize = Math.Min(blockSize, totalLength - startIndex);
                byte[] block = new byte[currentBlockSize];

                Array.Copy(body, startIndex, block, 0, currentBlockSize);
                CryptoHelper.DecryptAndEncrypt(block, md5Bytes, currentBlockSize);

                encryptedBody.AddRange(block);
                startIndex += currentBlockSize;
            }

            byte[] result = new byte[head.Length + encryptedBody.Count];
            Array.Copy(head, 0, result, 0, head.Length);
            Array.Copy(encryptedBody.ToArray(), 0, result, head.Length, encryptedBody.Count);

            return result;
        }

        public static byte[] CreateArray(byte[] md5)
        {
            byte[] key = new byte[52];
            Fill(key, (byte)0x02, 0, 20);
            Array.Copy(md5, 0, key, 20, md5.Length);

            byte[] sbox = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

            int esi = 0, edx = 0;
            uint ecx = 0;

            for (int j = 0; j < 256; j++)
            {
                uint eax = (uint)(sbox[esi] + key[edx]);
                ecx = (ecx + eax) & 0x800000FF;

                (sbox[esi], sbox[ecx]) = (sbox[ecx], sbox[esi]);

                edx = (int)(eax % 0x14);
                esi++;
            }

            return sbox;
        }

        public static void DecryptAndEncrypt(byte[] data, byte[] md5, int length)
        {
            byte[] sbox = CreateArray(md5);

            int iIndex = 0;
            uint jIndex = 0;

            for (int i = 0; i < length; i++)
            {
                iIndex = (iIndex + 1) & 0xFF;
                uint a = sbox[iIndex];
                jIndex = (jIndex + a) & 0xFF;
                (sbox[iIndex], sbox[jIndex]) = (sbox[jIndex], sbox[iIndex]);
                uint k = (uint)((sbox[iIndex] + sbox[jIndex]) & 0xFF);
                data[i] ^= sbox[k];
            }
        }

        public static string GetMd5()
        {
            string exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "GetKey", "GetMd5.exe");
            string outputPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MD5.txt");

            using (Process process = new Process())
            {
                process.StartInfo.FileName = exePath;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.Start();
            }

            for (int i = 1; i <= 100; i++)
            {
                Thread.Sleep(10);
                GetMd5Progress?.Invoke(null, new Progress(i));
            }

            if (!File.Exists(outputPath))
                throw new FileNotFoundException("MD5 file not found.", outputPath);

            return File.ReadAllText(outputPath).Trim();
        }

        public static string GetComputerCode()
        {
            StringBuilder sb = new StringBuilder(32);
            DllGetComputerCode(sb);
            return sb.ToString();
        }

        public static byte[] GetBaseIrsBytes()
        {
            return File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory + "\\GetKey", "Base.irs"));
        }

        public static void WriteTempIrs(byte[] data)
        {
            File.WriteAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory + "\\GetKey", "trInfoPf1.irs"), data);
        }

        public static void WritetrInfoPf1(byte[] data, string filPath)
        {
            File.WriteAllBytes(Path.Combine(filPath, "trInfoPf1.irs"), data);
        }

        public static void UpdateLicenseInfo(byte[] head, byte[] body, string computerCode, string md5, string use)
        {
            byte[] user = Encoding.ASCII.GetBytes(use);
            byte[] date = new byte[8] { 0x32, 0x30, 0x38, 0x38, 0x2f, 0x38, 0x2f, 0x38 };
            byte[] temp = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyzabcdef");

            Array.Copy(Encoding.ASCII.GetBytes(md5), 0, head, 15, md5.Length);
            Array.Copy(Encoding.ASCII.GetBytes(computerCode), 0, body, 1, computerCode.Length);
            Array.Copy(user, 0, body, 0x056, user.Length);
            Array.Copy(user, 0, body, 0x50b, user.Length);
            Array.Copy(user, 0, body, 0x9bd, user.Length);
            Array.Copy(user, 0, body, 0xe6f, user.Length);

            Array.Copy(date, 2, body, 0x040, date.Length - 2);
            Array.Copy(date, 0, body, 0x06a, date.Length);
            Array.Copy(date, 0, body, 0x9d1, date.Length);
            Array.Copy(date, 0, body, 0x4f3, date.Length);
            Array.Copy(date, 0, body, 0x9a5, date.Length);
            Array.Copy(date, 0, body, 0xe57, date.Length);
            Array.Copy(date, 0, body, 0xe83, date.Length);
            Array.Copy(date, 0, body, 0x51f, date.Length);

            Array.Copy(temp, 0, body, 0x0d2, temp.Length);
            Array.Copy(temp, 0, body, 0x587, temp.Length);
            Array.Copy(temp, 0, body, 0xa39, temp.Length);
            Array.Copy(temp, 0, body, 0xeeb, temp.Length);

            body[0x054] = 0xff; body[0x055] = 0xff;
            body[0x5fb] = 0xff; body[0x5fc] = 0xff;
            body[0x5ff] = 0xff; body[0x600] = 0xff;
            body[0x603] = 0xff; body[0x604] = 0xff;
            body[0x607] = 0xff; body[0x608] = 0xff;
            body[0x60b] = 0xff; body[0x60c] = 0xff;
            body[0x60f] = 0xff; body[0x610] = 0xff;
            body[0x613] = 0xff; body[0x614] = 0xff;
            body[0x617] = 0xff; body[0x618] = 0xff;
            body[0x61b] = 0xff; body[0x61c] = 0xff;
            body[0x61f] = 0xff; body[0x620] = 0xff;
            body[0x623] = 0xff; body[0x624] = 0xff;
            body[0x627] = 0xff; body[0x628] = 0xff;
            body[0x62b] = 0xff; body[0x62c] = 0xff;
            body[0x62f] = 0xff; body[0x630] = 0xff;
            body[0x633] = 0xff; body[0x634] = 0xff;
            body[0x637] = 0xff; body[0x638] = 0xff;
            body[0x63b] = 0xff; body[0x63c] = 0xff;
            body[0xaad] = 0xff; body[0xaae] = 0xff;
            body[0xab1] = 0xff; body[0xab2] = 0xff;
            body[0xab5] = 0xff; body[0xab6] = 0xff;
            body[0xab9] = 0xff; body[0xaba] = 0xff;
            body[0xabd] = 0xff; body[0xabe] = 0xff;
            body[0xac1] = 0xff; body[0xac2] = 0xff;
            body[0xac5] = 0xff; body[0xac6] = 0xff;
            body[0xac9] = 0xff; body[0xaca] = 0xff;
            body[0xf5f] = 0xff; body[0xf60] = 0xff;
            body[0xf63] = 0xff; body[0xf64] = 0xff;
            body[0xf67] = 0xff; body[0xf68] = 0xff;
            body[0xf6b] = 0xff; body[0xf6c] = 0xff;
            body[0xf6f] = 0xff; body[0xf70] = 0xff;
            body[0xf73] = 0xff; body[0xf74] = 0xff;
        }

        public static string GetRegCode(string str)
        {
            if (!int.TryParse(str, out int number))
                throw new ArgumentException("Input must be a valid integer string.", nameof(str));
            string hex = number.ToString("X8");
            StringBuilder sb = new StringBuilder(32);
            MD5(hex, sb);
            string desInput = hex + sb.ToString().Substring(8, 8);
            DllEncryptString_Des(sb, desInput);
            return sb.ToString();
        }

        public static void Fill<T>(T[] array, T value, int startIndex, int count)
        {
            for (int i = startIndex; i < startIndex + count; i++)
            {
                array[i] = value;
            }
        }
    }

    public class Progress : EventArgs
    {
        public int V2 { get; set; }

        public Progress(int v1)
        {
            V2 = v1;
        }
    }
}