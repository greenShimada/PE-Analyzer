using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing.Text;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualBasic.ApplicationServices;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;
using static PEAnalyzer.PEStructure_Class;

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
    public class PEManipulation
    {

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int InjectDLL([MarshalAs(UnmanagedType.LPStr)] string pathdll, [MarshalAs(UnmanagedType.LPStr)] string exe_name, ref PROCESS_INFORMATION processInformation);

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool InitializeSuspendedProcess(ref PROCESS_INFORMATION processInformation, [MarshalAs(UnmanagedType.LPStr)] string exe_name);

        [DllImport(@"dlls\InjectDllProject.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool ResumeMainThread(ref PROCESS_INFORMATION processInformation);

        private PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
        private string dllPath = (@"dlls\DllToBeInjected.dll").Replace("\\\\", "\\");
        private string path;
        public bool isPE;

        public IMAGE_DOS_HEADER dosHeader;
        public IMAGE_NT_HEADERS ntHeaders;
        public IMAGE_FILE_HEADER fileHeader;
        public IMAGE_OPTIONAL_HEADER optionalHeader;
        public IMAGE_DATA_DIRECTORY[] dataDirectory;

        public PEManipulation(string path){
            this.path = path;
            this.Static_Analysis();
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
        public void Static_Analysis()
        {
            // Lê os bytes do arquivo para dentro da array fileBytes
            byte[] fileBytes = File.ReadAllBytes(this.path);

            // Aloca fileBytes na memória protegendo seu conteúdo do Garbage Collector e criando um ponteiro estático na posição inicial da estrutura
            GCHandle handle = GCHandle.Alloc(fileBytes, GCHandleType.Pinned);

            // Atraves do ponteiro criado acima, ele lê os bytes (até o tamanho da struct definida em < >) e os coloca na variável dosHeader.
            this.dosHeader = Marshal.PtrToStructure<PEStructure_Class.IMAGE_DOS_HEADER>(handle.AddrOfPinnedObject());

            // Libera a área de memória do handle, permitindo o gabage collector a limpar ou mover essa área.
            handle.Free();

            // No formato PE, o endereço da assinatura PE (que marca o início do cabeçalho PE) está no endereço 3C do binário, apontado por e_lfanew na struct.
            int ntHeadersOffset = this.dosHeader.e_lfanew;
            
            byte[] ntHeadersBytes = new byte[Marshal.SizeOf(typeof(PEStructure_Class.IMAGE_NT_HEADERS))];

            // Copio de fileBytes, a quantidade de bytes do tamanho da struct N, os valores a partir do offset de e_lfanew para a posição 0 do ntHeaderBytes.
            Array.Copy(fileBytes, ntHeadersOffset, ntHeadersBytes, 0, ntHeadersBytes.Length);

            handle = GCHandle.Alloc(ntHeadersBytes, GCHandleType.Pinned);
            this.ntHeaders = Marshal.PtrToStructure<PEStructure_Class.IMAGE_NT_HEADERS>(handle.AddrOfPinnedObject());
            this.fileHeader = this.ntHeaders.FileHeader;
            this.optionalHeader = this.ntHeaders.OptionalHeader;
            this.dataDirectory = this.optionalHeader.DataDirectory;

            handle.Free();

            this.isPE = (ntHeaders.Signature == 0x4550);


        }

    }
}
