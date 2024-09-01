using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEAnalyzer
{
    internal class PEDicts
    {
        private static readonly Dictionary<ushort, string> MachineTypes = new Dictionary<ushort, string>
        {
            {0x0000,"Tipo não catalogado"},
            {0x0184,"Alpha AXP, 32-bit address space"},
            {0x0284,"Alpha 64, 64-bit address space or AXP 64"},
            {0x01d3,"Matsushita AM33"},
            {0x8664,"x64"},
            {0x01c0,"ARM little endian"},
            {0xaa64,"ARM64 little endian"},
            {0x01c4,"ARM Thumb-2 little endian"},
            {0x0ebc,"EFI byte code"},
            {0x014c,"Intel 386"},
            {0x0200,"Intel Itanium processor family"},
            {0x6232,"LoongArch 32-bit processor family"},
            {0x6264,"LoongArch 64-bit processor family"},
            {0x9041,"Mitsubishi M32R little endian"},
            {0x0266,"MIPS16"},
            {0x0366,"MIPS with FPU"},
            {0x0466,"MIPS16 with FPU"},
            {0x01f0,"Power PC little endian"},
            {0x01f1,"Power PC with floating point support"},
            {0x0166,"MIPS little endian"},
            {0x5032,"RISC-V 32-bit address space"},
            {0x5064,"RISC-V 64-bit address space"},
            {0x5128,"RISC-V 128-bit address space"},
            {0x01a2,"Hitachi SH3"},
            {0x01a3,"Hitachi SH3 DSP"},
            {0x01a6,"Hitachi SH4"},
            {0x01a8,"Hitachi SH5"},
            {0x01c2,"Thumb"},
            {0x0169,"MIPS little-endian WCE v2"}
        };
        public static string GetMachineName(ushort machineType)
        {
            return MachineTypes.TryGetValue(machineType, out var machineName) ? machineName : "Tipo não catalogado.";
        }

    }
}
