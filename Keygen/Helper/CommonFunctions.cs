using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.IO;
using System;

namespace Keygen
{
    internal static partial class CommonFunctions
    {
        public static byte[] CreateArray(byte[] md5)
        {
            byte[] byteArry2 = new byte[52];
            for (int i = 0; i < 20; i++)
                byteArry2[i] = 0x02;
            Array.Copy(md5, 0, byteArry2, 20, md5.Length);

            byte[] byteArry1 = new byte[256];
            for (int i = 0; i <= 255; i++)
            {
                byteArry1[i] = (byte)i;
            }
            int index1esi = 0;
            int index2edx = 0;
            UInt32 temp, edi, eax, ecx = 0;

            for (int j = 256; j > 0; j--)
            {
                temp = edi = byteArry1[index1esi];
                eax = byteArry2[index2edx];
                eax += edi;
                ecx += eax;
                ecx &= 0x800000ff;
                byteArry1[index1esi] = byteArry1[ecx];
                index2edx = (int)(eax % 0x14);
                index1esi++;
                byteArry1[ecx] = (byte)temp;
            }

            return byteArry1;
        }

        public static void DecryptAndEncrypt(byte[] Code, byte[] md5, int len)
        {
            byte[] createArray = CreateArray(md5);
            int index = 0;
            UInt32 temp1, temp2, temp3;
            UInt32 ebx = 0;

            for (int i = 0; i < len; i++)
            {
                index++;
                index &= 0xff;
                temp1 = temp3 = createArray[index];
                temp1 += ebx;
                temp1 &= 0xff;
                ebx = temp1;
                temp2 = createArray[ebx];
                createArray[index] = (byte)temp2;
                temp2 += temp3;
                temp2 &= 0xff;
                createArray[ebx] = (byte)temp3;
                byte dl = createArray[temp2];
                byte al = Code[i];
                byte re = (byte)(dl ^ al);
                Code[i] = (byte)re;
            }
        }

        public static string GetMd5()
        {
            Process process = new Process();
            process.StartInfo.FileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory + "\\GetKey", "GetMd5.exe");
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            process.Start();

            for (int i = 1; i <= 100; i++)
            {
                System.Threading.Thread.Sleep(10);
                GetMd5Progress?.Invoke(null, new Progress(i));
            }

            string str = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MD5.txt"));
            return str;
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

        public static void ChangeBody(byte[] head, byte[] body, string computerCode, string md5, string use)
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
            StringBuilder sb = new StringBuilder(32);
            string v = int.Parse(str).ToString("X8");
            MD5(v, sb);
            DllEncryptString_Des(sb, v + sb.ToString().Substring(8, 8));
            return sb.ToString();
        }
    }

    internal static partial class CommonFunctions
    {
        [DllImport(@"\GetKey\ArLib.dll", SetLastError = true)]
        private static extern int DllGetComputerCode(StringBuilder stringBuilder);

        [DllImport(@"\GetKey\ArLib.dll", SetLastError = true)]
        private static extern int DllEncryptString_Des(StringBuilder enc, string dec, string str = "Ld_Tq_Se");

        [DllImport(@"\GetKey\ArLib.dll", SetLastError = true)]
        private static extern int MD5(string a1, StringBuilder a2);

        public static event EventHandler GetMd5Progress;
    }
}