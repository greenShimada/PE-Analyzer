﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PEAnalyzer
{
    public class PEStructure_Class
    {

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
            public ushort Magic;                             // 0x020B para PE32+ (64 bits)
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;                          // 64 bits
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
            public ulong SizeOfStackReserve;                 // 64 bits
            public ulong SizeOfStackCommit;                  // 64 bits
            public ulong SizeOfHeapReserve;                   // 64 bits
            public ulong SizeOfHeapCommit;                    // 64 bits
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;     // Array de diretórios
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;    // RVA da tabela
            public uint Size;              // Tamanho da tabela
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

 
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            // Union in C# is represented by using explicit layout or separate fields.
            public uint OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
            public uint TimeDateStamp;      // 0 if not bound, -1 if bound, and real date\time stamp                                    // otherwise, date/time stamp of DLL bound to
            public int ForwarderChain;      // -1 if no forwarders
            public uint Name;               // RVA to the DLL name
            public uint FirstThunk;         // RVA to IAT (if bound this IAT has actual addresses)
        }
    }
}

