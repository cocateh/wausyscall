use std::env;
use std::str;
use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use std::path::Path;
use std::mem::size_of;
use regex::Regex;
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
    UnsupportedCoffMachine(u16),
    InvalidOptionalMagic,
    InvalidBitness,
    OffsetNotFound,
}

const DOS_MAGIC: &'static [u8; 2] = b"MZ";

const COFF_X86_MACHINE: u16 = 0x014c;
const COFF_X64_MACHINE: u16 = 0x8664;

// const DATA_DIRECTORIES: usize = 16;

const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;

// COFF header characteristics
// const IMAGE_FILE_DLL: u16 = 0x2000;

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

macro_rules! typed_consume {
    ($reader:expr, $type:ty, $field:expr) => {{
        let mut buf = [0u8; size_of::<$type>()];
        $reader.read_exact(&mut buf).map(|_| {
            <$type>::from_le_bytes(buf)
        }).map_err(|x| Error::FileRead($field, x))
    }};
}

macro_rules! native_consume {
    ($reader:expr, $bitness:ident, $field:expr) => {{
        match $bitness {
            Bitness::Bits64 => typed_consume!($reader, u64, $field),
            Bitness::Bits32 => typed_consume!($reader, u32, $field)
                .map(|x| x as u64),
        }
    }};
}

#[derive(Debug)]
enum Bitness {
    Bits64,
    Bits32,
}

impl TryFrom<u16> for Bitness {
    type Error = Error;
    fn try_from(val: u16) -> Result<Self> {
        match val {
            COFF_X86_MACHINE => Ok(Bitness::Bits32),
            COFF_X64_MACHINE => Ok(Bitness::Bits64),
            _ => Err(Error::InvalidBitness),
        }
    }
}

fn read_ntdll(file_path: impl AsRef<Path>,
              search_pattern: Option<String>) -> Result<()> {
    let mut reader = File::open(file_path).map_err(Error::FileOpen)?;
    
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

    let machine = typed_consume!(reader, u16, "COFF Machine")?;
    let bitness = Bitness::try_from(machine)
        .map_err(|_| Error::UnsupportedCoffMachine(machine))?;

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
    let _maj_os_ver = typed_consume!(reader, u16, "MajorOsVersion")?;
    let _min_os_ver = typed_consume!(reader, u16, "MinorOsVersion")?;
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

    let mut syscall_map: HashMap<String, u32> = HashMap::new();

    // Read exported names and match to syscall function naming format
    let syscall_regex = Regex::new("^Nt[A-Z][[:alpha:]]+").unwrap();
    for i in 0..name_vec.len() {
        let name = &name_vec[i];
        let ord: usize = ord_vec[i].into();
        let fun: u64 = fun_vec[ord].into();
        let fun_off = fun - text_vaddr as u64 + text_off as u64;
        if syscall_regex.is_match(name) {
            reader.seek(SeekFrom::Start(fun_off))
                .map_err(Error::FileSeek)?;

            /*
             * x86 windows syscall functions are constructed in format
             * mov r10, rcx ;; 3 byte instruction
             * mov eax, {syscall number} ;; 5 bytes instruction
             *
             * reading 4 bytes removes these unnecessary opcodes and leaves us
             * with 32 bit syscall number to read
             */
            let _opcodes = typed_consume!(reader, u32, "Useless opcodes")?;
            let syscall_num = typed_consume!(reader, u32, "Syscall number")?;
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
        println!("{} => {:#x}", name, number);
    }

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut ntdll_path: String = if env::consts::OS == "windows" {
        String::from("C:\\Windows\\System32\\ntdll.dll")
    } else {
        String::new()
    };

    if args.len() < 2 && ntdll_path.is_empty() {
        println!("err: usage {} <path to ntdll> (function name)", args[0]);
        return Ok(());
    } else if args.len() >= 2 && ntdll_path.is_empty() {
        ntdll_path = args[1].clone();
    }

    let search_pattern = if args.len() >= 3 { Some(args[2].clone()) }
                         else { None };

    read_ntdll(&ntdll_path, search_pattern)
}