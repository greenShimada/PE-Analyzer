using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualBasic.ApplicationServices;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;


[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}

namespace PEAnalyzer
{
    public class PEMonitor 
    {
     
        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int InjectDLL([MarshalAs(UnmanagedType.LPStr)] string pathdll, [MarshalAs(UnmanagedType.LPStr)] string exe_name, ref PROCESS_INFORMATION processInformation);

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool InitializeSuspendedProcess(ref PROCESS_INFORMATION processInformation, [MarshalAs(UnmanagedType.LPStr)] string exe_name);

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool ResumeMainThread(ref PROCESS_INFORMATION processInformation);


        private Process Process = new();
        public void StartProcess(string path)
        {
            try
            {
                using (this.Process = new Process())
                {
                    PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
                    int result;
                    string dll_path = @"dlls\DllToBeInjected.dll";
                    this.Process.StartInfo.FileName = path;
                    dll_path = dll_path.Replace("\\\\", "\\");

                    bool hasError;
                    hasError = InitializeSuspendedProcess(ref processInformation, path);
                    if (hasError) { }
                    result = InjectDLL(dll_path, path, ref processInformation);
                    
                    ResumeMainThread(ref processInformation);


                    // result = Inject_DLL(dll_path, path);


                    //if (result != 10) {
                    //    Console.WriteLine("opaopaopa");
                    //}

                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}
