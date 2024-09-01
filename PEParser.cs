using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;



namespace PEAnalyzer.PEParser
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
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(handle.AddrOfPinnedObject());
            
            // Libera a área de memória do handle, permitindo o gabage collector a limpar ou mover essa área.
            handle.Free();

            // No formato PE, o endereço da assinatura PE (que marca o início do cabeçalho PE) está no endereço 3C do binário, apontado por e_lfanew na struct.
            int ntHeadersOffset = dosHeader.e_lfanew;
            IMAGE_NT_HEADERS ntHeaders;
            byte[] ntHeadersBytes = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS))];

            // Copio de fileBytes, a quantidade de bytes do tamanho da struct N, os valores a partir do offset de e_lfanew para a posição 0 do ntHeaderBytes.
            Array.Copy(fileBytes, ntHeadersOffset, ntHeadersBytes, 0, ntHeadersBytes.Length);

            handle = GCHandle.Alloc(ntHeadersBytes, GCHandleType.Pinned);
            ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(handle.AddrOfPinnedObject());
            handle.Free();

            if (ntHeaders.Signature != 0x4550)
            {
                Debug.WriteLine("Não é um executável PE");
            }


        }


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;      // Número mágico
            public ushort e_cblp;       // Bytes na última página do arquivo
            public ushort e_cp;         // Páginas no arquivo
            public ushort e_crlc;       // Relocações
            public ushort e_cparhdr;    // Tamanho do cabeçalho em parágrafos
            public ushort e_minalloc;   // Mínimo de parágrafos adicionais necessários
            public ushort e_maxalloc;   // Máximo de parágrafos adicionais necessários
            public ushort e_ss;         // Valor inicial (relativo) de SS
            public ushort e_sp;         // Valor inicial de SP
            public ushort e_csum;       // Checksum
            public ushort e_ip;         // Valor inicial de IP
            public ushort e_cs;         // Valor inicial (relativo) de CS
            public ushort e_lfarlc;     // Endereço do arquivo da tabela de relocalização
            public ushort e_ovno;       // Número da sobreposição
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res;      // Palavras reservadas
            public ushort e_oemid;      // Identificador OEM (para e_oeminfo)
            public ushort e_oeminfo;    // Informação OEM; específica para e_oemid
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;     // Palavras reservadas
            public int e_lfanew;        // Endereço do novo cabeçalho EXE
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_NT_HEADERS
        {
            public uint Signature;            // "PE\0\0" (0x00004550)

            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
        }
    }
}
