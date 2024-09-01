using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using PEAnalyzer;


namespace PEAnalyzer
{
    public class PEParser
    {
        public static void pe_static_analysing(string path)
        {
            // Lê os bytes do arquivo para dentro da array fileBytes
            byte[] fileBytes = File.ReadAllBytes(path);

            // Aloca fileBytes na memória protegendo seu conteúdo do Garbage Collector e criando um ponteiro estático na posição inicial da estrutura
            GCHandle handle = GCHandle.Alloc(fileBytes, GCHandleType.Pinned);

            // Atraves do ponteiro criado acima, ele lê os bytes (até o tamanho da struct definida em < >) e os coloca na variável dosHeader.
            PEStructure_Class.IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<PEStructure_Class.IMAGE_DOS_HEADER>(handle.AddrOfPinnedObject());

            // Libera a área de memória do handle, permitindo o gabage collector a limpar ou mover essa área.
            handle.Free();

            // No formato PE, o endereço da assinatura PE (que marca o início do cabeçalho PE) está no endereço 3C do binário, apontado por e_lfanew na struct.
            int ntHeadersOffset = dosHeader.e_lfanew;
            PEStructure_Class.IMAGE_NT_HEADERS ntHeaders;
            byte[] ntHeadersBytes = new byte[Marshal.SizeOf(typeof(PEStructure_Class.IMAGE_NT_HEADERS))];

            // Copio de fileBytes, a quantidade de bytes do tamanho da struct N, os valores a partir do offset de e_lfanew para a posição 0 do ntHeaderBytes.
            Array.Copy(fileBytes, ntHeadersOffset, ntHeadersBytes, 0, ntHeadersBytes.Length);

            handle = GCHandle.Alloc(ntHeadersBytes, GCHandleType.Pinned);
            ntHeaders = Marshal.PtrToStructure<PEStructure_Class.IMAGE_NT_HEADERS>(handle.AddrOfPinnedObject());
            handle.Free();

            if (ntHeaders.Signature != 0x4550)
            {
                Debug.WriteLine("Não é um executável PE");
            }
            else
            {
                Debug.WriteLine("É um PE");
                Debug.WriteLine(PEDicts.GetMachineName(ntHeaders.FileHeader.Machine));
            }


        }


    }
}
