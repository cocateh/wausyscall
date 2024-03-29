use std::env;
use std::str;
use std::io::{Read, Seek, SeekFrom, BufReader};
use std::fs::File;
use std::path::Path;
use std::mem::size_of;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
enum Error {
    FileOpen(std::io::Error),
    FileRead(&'static str, std::io::Error),
    FileSeek(std::io::Error),
    InvalidDosMagic,
    InvalidCoffMagic,
    SeekErr(&'static str, std::io::Error),
    InvalidCoffMachine(u16),
    InvalidOptionalMagic,
    OffsetNotFound,
}

const DOS_MAGIC: &'static [u8; 2] = b"MZ";

const COFF_X86_MACHINE: u16 = 0x014c;
const COFF_AMD64_MACHINE: u16 = 0x8664;
const COFF_R4000_MACHINE: u16 = 0x166;
const COFF_AARCH64_MACHINE: u16 = 0xAA64;
const COFF_ITANIUM_MACHINE: u16 = 0x0200;
const COFF_POWERPC_MACHINE: u16 = 0x01f0;
const COFF_ALPHA_MACHINE: u16 = 0x0184;
const COFF_THUMB2_MACHINE: u16  = 0x01c4;

// const DATA_DIRECTORIES: usize = 16;

const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;

// COFF header characteristics
// const IMAGE_FILE_DLL: u16 = 0x2000;

/// Consume bytes from $reader.
macro_rules! consume {
    ($reader:expr) => {{
        let mut buf = [0u8; 1];
        $reader.read_exact(&mut buf).map(|_| buf[0])
            .map_err(|x| Error::FileRead("eating bytes", x))
    }};
    ($reader:expr, $field:expr) => {{
        let mut buf = [0u8; 1];
        $reader.read_exact(&mut buf).map(|_| buf)
            .map_err(|x| Error::FileRead($field, x))
    }};
    ($reader:expr, $size:expr, $field:expr) => {{
        let mut buf = [0u8; $size];
        $reader.read_exact(&mut buf).map(|_| buf)
            .map_err(|x| Error::FileRead($field, x))
    }};
}

/// Consume size_of<$type> bytes from $reader and return $type.
macro_rules! typed_consume {
    ($reader:expr, $type:ty, $field:expr) => {{
        let mut buf = [0u8; size_of::<$type>()];
        $reader.read_exact(&mut buf).map(|_| {
            <$type>::from_le_bytes(buf)
        }).map_err(|x| Error::FileRead($field, x))
    }};
}

/// Consume either 4 or 8 bytes and return u32 or u64 depending on target CPU.
macro_rules! native_consume {
    ($reader:expr, $bitness:ident, $field:expr) => {{
        match $bitness {
            Bitness::Bits64 => typed_consume!($reader, u64, $field),
            Bitness::Bits32 => typed_consume!($reader, u32, $field)
                .map(|x| x as u64),
        }
    }};
}

#[derive(Debug, Clone, Copy)]
enum Machine {
    X86,
    AMD64,
    R4000,
    AArch64,
    Alpha,
    PowerPC,
    Itanium,
    Thumb2,
}

impl TryFrom<u16> for Machine {
    type Error = Error;
    fn try_from(val: u16) -> Result<Self> {
        match val {
            COFF_X86_MACHINE     => Ok(Machine::X86),
            COFF_AMD64_MACHINE   => Ok(Machine::AMD64),
            COFF_R4000_MACHINE   => Ok(Machine::R4000),
            COFF_AARCH64_MACHINE => Ok(Machine::AArch64),
            COFF_POWERPC_MACHINE => Ok(Machine::PowerPC),
            COFF_ALPHA_MACHINE   => Ok(Machine::Alpha),
            COFF_ITANIUM_MACHINE => Ok(Machine::Itanium),
            COFF_THUMB2_MACHINE  => Ok(Machine::Thumb2),
            _                    => Err(Error::InvalidCoffMachine(val)),
        }
    }
}

impl TryInto<u16> for Machine {
    type Error = Error;
    fn try_into(self) -> Result<u16> {
        match self {
            Machine::X86     => Ok(COFF_X86_MACHINE),
            Machine::AMD64   => Ok(COFF_AMD64_MACHINE),
            Machine::R4000   => Ok(COFF_R4000_MACHINE),
            Machine::AArch64 => Ok(COFF_AARCH64_MACHINE),
            Machine::Alpha   => Ok(COFF_ALPHA_MACHINE),
            Machine::PowerPC => Ok(COFF_POWERPC_MACHINE),
            Machine::Itanium => Ok(COFF_ITANIUM_MACHINE),
            Machine::Thumb2  => Ok(COFF_THUMB2_MACHINE),
        }
    }
}

#[derive(Debug)]
enum Bitness {
    Bits64,
    Bits32,
}

impl TryFrom<Machine> for Bitness {
    type Error = Error;
    fn try_from(val: Machine) -> Result<Self> {
        match val {
            Machine::AMD64   => Ok(Bitness::Bits64),
            Machine::AArch64 => Ok(Bitness::Bits64),
            Machine::Itanium => Ok(Bitness::Bits64),

            // Windows used 32 bit exclusively until Windows XP
            Machine::R4000   => Ok(Bitness::Bits32),
            Machine::Alpha   => Ok(Bitness::Bits32),
            Machine::PowerPC => Ok(Bitness::Bits32),
            Machine::X86     => Ok(Bitness::Bits32),
            Machine::Thumb2  => Ok(Bitness::Bits32),
        }
    }
}

/// Read Alpha syscall
fn read_alpha_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * lda $0, {syscall number}($31) ;; r32 is a zero register
     * call_pal callsys              ;; somekind of syscall invkoing mechanism
     */
    typed_consume!(reader, u16, "Syscall number")
}

/// Read PowerPC syscall
fn read_ppc_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * PowerPC uses syscall wrappers, cause there is no simple way of
     * making syscalls.
     *
     * Example:
     * addi r0, 0, {syscall number} ;; or li r0, {syscall number}
     * b syscall_wrapper
     */
    typed_consume!(reader, u16, "Syscall number")
}

/// Read Itanium syscall
fn read_itanium_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * Itanium is hella weird.
     * So because of weird instruction encoding and operand sizes we have to
     * fuck around.
     * mov takes a 22 bit immediate which we want parse into sane 16 bit,
     * so we don't even have to read the whole bundle or even a whole slot.
     *
     * Example syscall (im trusting IDA output):
     * mov r8 = {syscall number}
     * movl r2 = 0xE0000000FFA0020;; # move KiFastSystemCall address
     * nop.m 0                       # padding?
     * mov b6 = r2                   # move address to branch register
     * br.few b6;;                   # branch off
     */
    let bundle = consume!(reader, 5, "Itanium instruction bundle")?;
    let mut value_bytes = [0u8; 2];
    value_bytes[0] = ((bundle[1] & 0b00000011) << 6) |
                     ((bundle[2] & 0b11111100) >> 2);
    value_bytes[1] = ((bundle[2] & 0b00000011) << 6) |
                     ((bundle[3] & 0b11111100) >> 2);
    Ok(u16::from_le_bytes(value_bytes))
}

#[allow(dead_code, unreachable_code, unused_parens, unused_mut, unused_variables)]
/// Read Thumb2 syscall
fn read_thumb2_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * There were not many releases of 32 bit ARM Windows although its
     * syscall calling convention is similar to Linux. Thumb has
     * variable sized instructions (either 32 or 16 bit, not as variable as x86).
     * What I find a bit odd is that it uses either mov or movw which makes me
     * parse both variants.
     *
     * Example:
     * mov/movw r12, #0x33 ;; syscall number
     * svc 0x1             ;; supervisor call
     * bx lr               ;; return
     *
     * Instruction encoding for 12-bit immediate mov
     *      (why Ghidra doesn't show mask bit for the sign??. This is 11 bits):
     * 00000000 00000000 11111111 01110000
     *
     * Instruction encoding for 16-bit immediate movw:
     * 00001111 00000100 11111111 01110000
     */
    unimplemented!("Thumb2 is not yet implemented!");
    let mov_instruction = consume!(reader, 4, "MOV instruction")?;
    let mut value_bytes = [0u8; 2];
    if (mov_instruction[1] & 0b00000011) == 0b00000000 {
    } else if ((mov_instruction[1] & 0b00000011) == 0b00000010) {
    }
    Ok(u16::from_le_bytes(value_bytes))
}

/// Read AArch64 syscall
fn read_aarch64_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * AArch64 Windows uses SVC instruction for syscalls and in contrast to
     * linux, it uses the exception number in an instruction for syscalls,
     * which requires us to use value mask on the instruction and then just
     * align the bits correcly.
     *
     * Example:
     * svc {syscall_number}
     *
     * Immediate mask for little-endian values:
     * 11100000 11111111 00011111 00000000
     */
    let svc_instruction = consume!(reader, 4, "SVC instruction")?;
    let mut value_bytes = [0u8; 2];
    value_bytes[0] = ((svc_instruction[1] & 0b00011111) << 3) |
                     ((svc_instruction[0] & 0b11100000) >> 5);
    value_bytes[1] = ((svc_instruction[2] & 0b00011111) << 3) |
                     ((svc_instruction[1] & 0b11100000) >> 5);
    Ok(u16::from_le_bytes(value_bytes))
}

/// Read MIPS R4000 syscall
fn read_r4000_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * Windows uses little endian on every platform,
     * and MIPS encodes immediate instructions to have 16 byte immediate
     * operands.
     *
     * Example:
     * addiu $zero, ${syscall_num}
     * syscall
     */
    typed_consume!(reader, u16, "Syscall number")
}

/// Read x86 syscall for Windows 8 and higher
fn read_x86_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * Windows 8 <= syscall functions are constructed in format
     * mov r10, rcx              ;; 3 byte instruction
     * mov eax, {syscall number} ;; 5 bytes instruction
     *
     * reading 4 bytes removes these unnecessary opcodes and leaves us
     * with 32 bit syscall number to read
     */
    let _opcodes = typed_consume!(reader, u32, "Useless opcodes")?;
    typed_consume!(reader, u16, "Syscall number")
}

/// Read x86 syscall for Windows XP and lower
fn read_old_syscall(mut reader: impl Read) -> Result<u16> {
    /*
     * Windows XP up to 7 used a different syscall convention.
     * Syscall functions called a KiFastSystemCall or KiFastSystemCallRet
     * which does sysenter. Calling convention for syscalls is __stdcall
     * for arguments and eax for syscall numbers.
     *
     * NtTerminateProcess:
     * mov eax, 101h             ;; 5 byte instruction
     * mov edx, KiFastSystemCall
     * call [edx]
     *
     * Windows 2000 >= doesn't use KiFastSystemCall in favour of int 2eh
     * but this parsing format is basically the same
     */
    let _opcodes = consume!(reader, 1, "Useless opcodes")?;
    typed_consume!(reader, u16, "Syscall number")
}

/// Read syscalls from file at file_path.
///
/// If search_pattern is not None, print only syscalls containing specified
/// string.
///
/// If print_errors is true, print only syscalls that are likely to
/// be incorrectly parsed.
fn parse_syscalls(file_path: impl AsRef<Path>,
              search_pattern: Option<String>,
              print_errors: bool) -> Result<()> {
    let mut reader =
        BufReader::new(File::open(file_path).map_err(Error::FileOpen)?);

    if &consume!(reader, 2, "e_magic")? != DOS_MAGIC {
        return Err(Error::InvalidDosMagic);
    }

    // Seek to e_lfanew
    reader.seek(SeekFrom::Start(0x3c))
        .map_err(|x| Error::SeekErr("couldn't seek to e_lfanew", x))?;

    let lfanew: u32 =
        <u32>::from_le_bytes(consume!(reader, 4, "e_lfanew")?);

    reader.seek(SeekFrom::Start(lfanew as u64))
        .map_err(|x| Error::SeekErr("couldn't seek to coff header", x))?;

    // _IMAGE_NT_HEADERS

    if &consume!(reader, 4, "NTSIGNATURE")? != b"PE\x00\x00" {
        return Err(Error::InvalidCoffMagic);
    }

    let machine = Machine::try_from(typed_consume!(reader, u16,
        "COFF Machine")?)?;
    let bitness = Bitness::try_from(machine)?;

    let section_count = typed_consume!(reader, u16, "NumberOfSections")?;
    let _time_stamp = typed_consume!(reader, u32, "TimeDateStamp")?;
    let _sym_ptr = typed_consume!(reader, u32, "PointerToSymbolTable")?;
    let _sym_count = typed_consume!(reader, u32, "NumberOfSymbols")?;
    let _opt_size = typed_consume!(reader, u16, "SizeOfOptionalHeader")?;
    let _flags = typed_consume!(reader, u16, "Characteristics")?;
    /*
    if u16::from(flags ^ IMAGE_FILE_DLL) >> 16 as u16 != 0 {
        println!("{:x}", flags);
        return Err(Error::NoDll);
    }
    */

    // COFF standard optional header
    let _opt_header_off = reader.stream_position()
        .map_err(Error::FileSeek)?;

    let coff_magic = typed_consume!(reader, u16, "Magic")?;
    if coff_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
       coff_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err(Error::InvalidOptionalMagic);
    }
    let _maj_link_ver = typed_consume!(reader, u8, "MajorLinkerVersion")?;
    let _min_link_ver = typed_consume!(reader, u8, "MinorLinkerVersion")?;
    let _codesize = typed_consume!(reader, u32, "SizeOfCode")?;
    let _init_size = typed_consume!(reader, u32, "SizeOfInitializedData")?;
    let _uninit_size = typed_consume!(reader, u32, "SizeOfUninitializedData")?;
    let _addr_entr = typed_consume!(reader, u32, "AddressOfEntryPoint")?;
    let _code_base = typed_consume!(reader, u32, "BaseOfCode")?;
    if let Bitness::Bits32 = bitness {
        reader.seek(SeekFrom::Current(4))
            .map_err(|x| Error::SeekErr("coudln't skip BaseOfData", x))?;
    }

    // NT fields
    let _image_base = native_consume!(reader, bitness, "ImageBase")?;
    let _sect_align = typed_consume!(reader, u32, "SectionAlignment")?;
    let _file_align = typed_consume!(reader, u32, "FileAlignment")?;
    let maj_os_ver = typed_consume!(reader, u16, "MajorOsVersion")?;
    let min_os_ver = typed_consume!(reader, u16, "MinorOsVersion")?;
    let _maj_img_ver = typed_consume!(reader, u16, "MajorImageVersion")?;
    let _maj_img_ver = typed_consume!(reader, u16, "MinorImageVersion")?;
    let _maj_sub_ver = typed_consume!(reader, u16, "MajorSubsystemVersion")?;
    let _maj_sub_ver = typed_consume!(reader, u16, "MinorSubsystemVersion")?;
    let _reserved = typed_consume!(reader, u32, "Win32VersionValue")?;
    let _img_size = typed_consume!(reader, u32, "SizeOfImage")?;
    let _hdr_size = typed_consume!(reader, u32, "SizeOfHeaders")?;
    let _chksum = typed_consume!(reader, u32, "CheckSum")?;
    let _subsys = typed_consume!(reader, u16, "Subsystem")?;
    let _dllflags = typed_consume!(reader, u16, "DllCharacteristics")?;
    let _stk_res_count = native_consume!(reader, bitness,
                                         "SizeOfStackReserve")?;
    let _stk_cmt_count = native_consume!(reader, bitness,
                                         "SizeOfStackCommit")?;
    let _heap_res_count = native_consume!(reader, bitness,
                                          "SizeOfHeapReserve")?;
    let _heap_res_count = native_consume!(reader, bitness,
                                          "SizeOfHeapCommit")?;
    let _ldrflags = typed_consume!(reader, u32, "LoaderFlags")?;
    let _size_rva_count = typed_consume!(reader, u32, "NumberOfRvaAndSizes")?;

    // Data directories
    // Export directory
    let export_rvaddr = typed_consume!(reader, u32, "Export Dir vaddr")?;
    let _export_size = typed_consume!(reader, u32, "Export Dir size")?;

    reader.seek(SeekFrom::Current(8 * (16 - 1)))
        .map_err(Error::FileSeek)?;

    let _sections_offset = reader.stream_position()
        .map_err(Error::FileSeek)?;

    // Find section containing export data
    let mut export_entry_off: u32 = 0;
    let mut sect_vaddr: u32 = 0;
    let mut sect_raw_off: u32 = 0;
    let mut text_vaddr: u32 = 0;
    let mut text_off: u32 = 0;
    for _ in 0..section_count {
        let name_bytes = consume!(reader, 8, "Section name")?;
        let mut section_name = name_bytes.iter().map(|&x| x as char)
            .collect::<String>();

        // Remove trailing null bytes
        section_name.retain(|c| c != (0x00 as char));

        let _virt_size = typed_consume!(reader, u32, "Section VirtualSize")?;
        let virt_addr = typed_consume!(reader, u32, "Section VirtualAddr")?;
        let raw_data_size = typed_consume!(reader, u32,
                                           "Section RawDataSize")?;
        let raw_data_ptr = typed_consume!(reader, u32,
                                          "Section PointerToRawData")?;
        let _reloc_ptr = typed_consume!(reader, u32,
                                        "Section PointerToRelocations")?;
        let _linum_ptr = typed_consume!(reader, u32,
                                        "Section PointerToLinenumbers")?;
        let _reloc_count = typed_consume!(reader, u16,
                                          "Section NumberOfRelocations")?;
        let _linum_count = typed_consume!(reader, u16,
                                          "Section NumberOfLinenumbers")?;
        let _secti_flags = typed_consume!(reader, u32,
                                          "Section Characteristics")?;
        if section_name == ".text" {
            // Finding .text section to resolve offsets to function exports
            text_vaddr = virt_addr;
            text_off = raw_data_ptr;
        }
        if virt_addr <= export_rvaddr &&
           virt_addr + raw_data_size > export_rvaddr
        {
            // Section found
            // Calculcating file offset from relative virtual address
            export_entry_off = export_rvaddr - virt_addr + raw_data_ptr;
            sect_vaddr = virt_addr;
            sect_raw_off = raw_data_ptr;
            break;
        }
    }

    if export_entry_off == 0 {
        return Err(Error::OffsetNotFound);
    }

    if text_off == 0 {
        return Err(Error::OffsetNotFound);
    }

    reader.seek(SeekFrom::Start(export_entry_off as u64))
        .map_err(Error::FileSeek)?;

    // IMAGE_DIRECTORY_ENTRY_EXPORT
    let _dir_flags = typed_consume!(reader, u32,
                                    "ExportDir Characteristics")?;
    let _dir_time = typed_consume!(reader, u32,
                                   "ExportDir TimeDateStamp")?;
    let _dir_maj = typed_consume!(reader, u16,
                                  "ExportDir MajorVersion")?;
    let _dir_min = typed_consume!(reader, u16,
                                  "ExportDir MinorVersion")?;
    let _dir_name = typed_consume!(reader, u32,
                                   "ExportDir Name")?;
    let _dir_base = typed_consume!(reader, u32,
                                   "ExportDir Base")?;
    let dir_fnum = typed_consume!(reader, u32,
                                  "ExportDir NumberOfFunctions")?;
    let dir_nnum = typed_consume!(reader, u32,
                                  "ExportDir NumberOfNames")?;
    let dir_rvfaddr = typed_consume!(reader, u32,
                                     "ExportDir AddressOfFunctions")?;
    let dir_rvnaddr = typed_consume!(reader, u32,
                                     "ExportDir AddressOfNames")?;
    let dir_rvoaddr = typed_consume!(reader, u32,
                                     "ExportDir AddressOfNameOrdinals")?;

    let names_off = dir_rvnaddr - sect_vaddr + sect_raw_off;
    let ord_off = dir_rvoaddr - sect_vaddr + sect_raw_off;
    let addr_off = dir_rvfaddr - sect_vaddr + sect_raw_off;

    // Reading Export tables: AddressOfNames, etc...
    reader.seek(SeekFrom::Start(names_off as u64))
        .map_err(Error::FileSeek)?;

    let mut name_vec: Vec<String> = Vec::new();
    let mut ord_vec: Vec<u16> = Vec::new();
    let mut fun_vec: Vec<u32> = Vec::new();

    // AddressOfNames
    for _ in 0..dir_nnum {
        let mut buf: Vec<u8> = Vec::new();
        let mut byte: u8;
        let str_addr = typed_consume!(reader, u32, "String Address")?;
        let str_off = str_addr - sect_vaddr + sect_raw_off;
        let prev_pos = reader.stream_position()
            .map_err(Error::FileSeek)?;
        reader.seek(SeekFrom::Start(str_off as u64))
            .map_err(Error::FileSeek)?;
        loop {
            byte = consume!(reader)?;
            if byte == 0x00 {
                break;
            }
            buf.push(byte);
        }
        let ready_string = buf.iter().map(|&c| c as char)
            .collect::<String>();
        name_vec.push(ready_string);
        reader.seek(SeekFrom::Start(prev_pos))
            .map_err(Error::FileSeek)?;
    }

    // AddressOfNameOrdinals
    reader.seek(SeekFrom::Start(ord_off as u64))
        .map_err(Error::FileSeek)?;

    for _ in 0..dir_nnum {
        let ord = typed_consume!(reader, u16, "Name Ordinal")?;
        ord_vec.push(ord);
    }

    // AddressOfFunctions
    reader.seek(SeekFrom::Start(addr_off as u64))
        .map_err(Error::FileSeek)?;

    for _ in 0..dir_fnum {
        let fun_addr = typed_consume!(reader, u32, "Export address")?;
        fun_vec.push(fun_addr);
    }

    let mut syscall_map: HashMap<String, u16> = HashMap::new();

    // Read exported names and match to syscall function naming format
    for i in 0..name_vec.len() {
        let name = &name_vec[i];
        let ord: usize = ord_vec[i].into();
        let fun: u64 = fun_vec[ord].into();
        let fun_off = fun - text_vaddr as u64 + text_off as u64;
        if name[0..2].starts_with("Nt") && name.chars().nth(2).is_some()
            && name.chars().nth(2).unwrap().is_ascii_uppercase()
        {
            let syscall_num: u16;
            reader.seek(SeekFrom::Start(fun_off))
                .map_err(Error::FileSeek)?;

            if let Machine::X86 = machine {
                if maj_os_ver == 6 && min_os_ver >= 2 || maj_os_ver > 6 {
                    syscall_num = read_x86_syscall(&mut reader)?;
                } else {
                    syscall_num = read_old_syscall(&mut reader)?;
                }
            } else if let Machine::AMD64 = machine {
                if maj_os_ver == 6 && min_os_ver >= 2 || maj_os_ver > 6 {
                    syscall_num = read_x86_syscall(&mut reader)?;
                } else {
                    syscall_num = read_old_syscall(&mut reader)?;
                }
            } else if let Machine::R4000 = machine {
                syscall_num = read_r4000_syscall(&mut reader)?;
            } else if let Machine::AArch64 = machine {
                syscall_num = read_aarch64_syscall(&mut reader)?;
            } else if let Machine::Alpha = machine {
                syscall_num = read_alpha_syscall(&mut reader)?;
            } else if let Machine::PowerPC = machine {
                syscall_num = read_ppc_syscall(&mut reader)?;
            } else if let Machine::Itanium = machine {
                syscall_num = read_itanium_syscall(&mut reader)?;
            } else if let Machine::Thumb2 = machine {
                syscall_num = read_thumb2_syscall(&mut reader)?;
            } else {
                return Err(Error::InvalidCoffMachine(machine.try_into()?))
            }

            syscall_map.insert(name.to_string(), syscall_num);
        }
    }

    for (name, number) in syscall_map.iter() {
        // If specified, print only functions that match the search pattern
        if let Some(ref val) = search_pattern {
            if !name.contains(val) {
                continue;
            }
        }

        /*
         * Most syscalls are in range of 0x000 - 0x200 for ntoskrnl
         * and 0x100 > && < 0x2000 for win32k.
         * If number value is not in that range, the syscall function
         * most likely doesn't follow the pattern described before.
         */
        if number.to_owned() >= 0x2000 {
            println!("(likely erroneus) {}: {:#x}", name, number);
        } else {
            if print_errors == true {
                continue;
            }
            println!("{}: {:#x}", name, number);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let mut args: Vec<String> = env::args().collect();
    let mut print_errors: bool = false;
    let mut print_help: bool = false;
    let mut file_path: String = if env::consts::OS == "windows" {
        String::from("C:\\Windows\\System32\\ntdll.dll")
    } else {
        String::new()
    };

    args.retain(|x| {
        if x == "--only-erroneus" {
            print_errors = true;

            // Discard from argument list
            false
        } else { true }
    });

    args.retain(|x| {
        if x == "--help" {
            print_help = true;

            false
        } else { true }
    });

    if (args.len() < 2 && file_path.is_empty()) || print_help {
        println!(
r#"usage: {} <path> (function name) [--only-erroneus]
    <path>          - path to usermode dll containing syscall numbers,
    like win32u.dll or ntdll.dll. On Windows, if not present, defaults to
    "C:\Windows\system32\ntdll.dll". On different system, this argument is
    required.
    (function name) - If passed, prints only functions containing this string
    and matching syscall regex.
    --only-erroneus - Print only functions that are likely improperly parsed."#,
    args[0]);
        return Ok(());
    } else if args.len() >= 2 {
        file_path = args[1].clone();
    }

    let search_pattern = if args.len() >= 3 { Some(args[2].clone()) }
                         else { None };

    parse_syscalls(&file_path, search_pattern, print_errors)
}
