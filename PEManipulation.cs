using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing.Text;
using System.Linq;
using System.Reflection.Metadata;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualBasic.ApplicationServices;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;
using static PEAnalyzer.PEStructure_Class;

namespace PEAnalyzer
{
    using HMODULE = IntPtr;
    using DWORD = uint;
    public class PEManipulation
    {

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int InjectDLL([MarshalAs(UnmanagedType.LPStr)] string pathdll, [MarshalAs(UnmanagedType.LPStr)] string exe_name, ref PROCESS_INFORMATION processInformation);

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool InitializeSuspendedProcess(ref PROCESS_INFORMATION processInformation, [MarshalAs(UnmanagedType.LPStr)] string exe_name);

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool ResumeMainThread(ref PROCESS_INFORMATION processInformation);

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool FillPEStructure(ref PROCESS_INFORMATION processInformation, ref IMAGE_DOS_HEADER dosHeader, ref IMAGE_NT_HEADERS ntHeaders, [MarshalAs(UnmanagedType.LPStr)] string moduleName);


        private PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
        private string dllPath = (@"dlls\DllToBeInjected.dll").Replace("\\\\", "\\");
        private string path;

        public IMAGE_DOS_HEADER dosHeader = default(IMAGE_DOS_HEADER);
        public IMAGE_NT_HEADERS ntHeaders = default(IMAGE_NT_HEADERS);
        public IMAGE_FILE_HEADER fileHeader = default(IMAGE_FILE_HEADER);
        public IMAGE_OPTIONAL_HEADER optionalHeader = default(IMAGE_OPTIONAL_HEADER);
        public IMAGE_DATA_DIRECTORY dataDirectory = default(IMAGE_DATA_DIRECTORY);
        public IMAGE_IMPORT_DESCRIPTOR pImportAddressTable = default(IMAGE_IMPORT_DESCRIPTOR);

        public long iatSize;
        public PEManipulation(string path){
            this.path = path;
            return;
        }
        public bool _FillPEStructure()
        {
            return FillPEStructure(ref this.processInformation, ref this.dosHeader, ref this.ntHeaders,  this.path);
        }
        public bool _InitializeSuspendedProcess()
        {
            try
            {
                {
                    bool hasError;
                    hasError = InitializeSuspendedProcess(ref this.processInformation, this.path);
                    if (hasError) { throw new Exception("Erro ao inicializar o proceso."); return false; }
                    return true;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }
        public bool _InjectDLL()
        {
            int result;
            result = InjectDLL(this.dllPath, this.path, ref this.processInformation);
            if (result != 10) { throw new Exception("Erro ao injetar DLL no proceso."); return false; }
            return true;
        }
        public bool _ResumeMainThread()
        {
            ResumeMainThread(ref this.processInformation);
            return true;
        }
        public bool isPE()
        {
            IMAGE_DOS_HEADER _dosHeader;
            IMAGE_NT_HEADERS _ntHeaders;

            byte[] fileBytes = File.ReadAllBytes(this.path);
            GCHandle handle = GCHandle.Alloc(fileBytes, GCHandleType.Pinned);
            _dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(handle.AddrOfPinnedObject());
            handle.Free();
            int ntHeadersOffset = _dosHeader.e_lfanew;
            byte[] ntHeadersBytes = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS))];
            Array.Copy(fileBytes, ntHeadersOffset, ntHeadersBytes, 0, ntHeadersBytes.Length);

            handle = GCHandle.Alloc(ntHeadersBytes, GCHandleType.Pinned);
            _ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(handle.AddrOfPinnedObject());
            handle.Free();

            return (_ntHeaders.Signature == 0x4550 && _dosHeader.e_magic == 0x5A4D);


        }

    }
}
