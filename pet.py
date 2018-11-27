#!/usr/bin/env python3

from enum import Enum, unique
import sys, struct

# PET = Pythone Elf Tool

PET_VERSION_MAJOR = 0
PET_VERSION_MINOR = 1

@unique
class ElfClass(Enum):
    NONE = 0
    CLASS32 = 1
    CLASS64 = 2

@unique
class ElfData(Enum):
    UNKNOWN = 0
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

@unique
class ElfOSABI(Enum):
    UNIX_SYSV = 0
    HPUX = 1
    NETBSD = 2
    LINUX = 3
    SOLARIS = 6
    AIX = 7
    IRIX = 8
    FREEBSD = 9
    TRU64 = 10
    MODESTO = 11
    OPENBSD = 12
    ARM_AEABI = 64
    ARM = 97
    STANDALONE = 255


def gen_reverse_lookup_table(enum_obj):
    ret = {}
    for i in enum_obj.__members__.keys():
        ret[enum_obj.__members__[i].value] = enum_obj.__members__[i]
    return ret

ElfOSABI_reverse_lookup = gen_reverse_lookup_table(ElfOSABI)

@unique
class ElfObjType(Enum):
    NONE = 0
    REL = 1
    EXEC = 2
    DYN = 3
    CORE = 4

ElfObjType_reverse_lookup = gen_reverse_lookup_table(ElfObjType)


@unique
class ElfMachine(Enum):
    NONE = 0
    X86_64 = 62
    RISCV = 243
    BPF = 247

ElfMachine_reverse_lookup = gen_reverse_lookup_table(ElfMachine)


@unique
class ElfVersion(Enum):
    NONE = 0
    CURRENT = 1

def get_elf_version(code):
    if code == 1:
        return ElfVersion.CURRENT
    else:
        return ElfVersion.NONE

@unique
class ElfSectionType(Enum):
    NULL          = 0
    PROGBITS      = 1
    SYMBOL_TABLE  = 2
    STR_TABLE     = 3
    RELA          = 4
    HASH          = 5
    DYNAMIC       = 6
    NOTE          = 7
    NOBITS        = 8
    REL           = 9
    SHLIB         = 10
    DYNSYM        = 11
    INIT_ARRAY    = 14
    FINI_ARRAY    = 15
    PREINIT_ARRAY = 16
    GROUP         = 17
    SYMTAB_SHNDX  = 18
    GNU_HASH      = 0x6ffffff6
    GNU_LIBLIST   = 0x6ffffff7
    CHECKSUM      = 0x6ffffff8
    SUNW_move     = 0x6ffffffa
    SUNW_COMDAT   = 0x6ffffffb
    SUNW_syminfo  = 0x6ffffffc
    GNU_verdef    = 0x6ffffffd
    GNU_verneed   = 0x6ffffffe
    GNU_versym    = 0x6fffffff
    LOPROC        = 0x70000000
    HIPROC        = 0x7fffffff
    LOUSER        = 0x80000000
    HIUSER        = 0x8fffffff

ElfSectionType_reverse_lookup = gen_reverse_lookup_table(ElfSectionType)

class ElfIdent:
    ELF_IDENT_SIZE = 16
    def __init__(self, bindata):
        tmp = struct.unpack("B"*ElfIdent.ELF_IDENT_SIZE, bindata)
        if not self.__is_elfmagic(tmp[0:4]):
            return False
        self.MAGIC0 = tmp[0]
        self.MAGIC1 = tmp[1]
        self.MAGIC2 = tmp[2]
        self.MAGIC3 = tmp[3]
        self.CLASS  = self.__get_class(tmp[4])
        self.DATA_ENCODE = self.__get_data_encode(tmp[5])
        self.VERSION = get_elf_version(tmp[6])
        self.OSABI = self.__get_osabi(tmp[7])
        self.ABIVER = tmp[8]
        self.PAD = tmp[9]

    def __is_elfmagic(self, tup):
        ELFMAGIC = (0x7F, ord('E'), ord('L'), ord('F'))
        for i, j in zip(ELFMAGIC, tup):
            if i != j:
                return False
        return True

    def __get_class(self, code):
        if code == 1:
            return ElfClass.CLASS32
        elif code == 2:
            return ElfClass.CLASS64
        else:
            return ElfClass.NONE

    def __get_data_encode(self, code):
        if code == 1:
            return ElfData.LITTLE_ENDIAN
        elif code == 2:
            return ElfData.BIG_ENDIAN
        else:
            return ElfData.UNKNOWN

    def __get_osabi(self, code):
        return ElfOSABI_reverse_lookup[code]

    def __str__(self):
        magic = "MAGIC = {:x} {:x} {:x} {:x}" \
                    .format(self.MAGIC0,
                            self.MAGIC1,
                            self.MAGIC2,
                            self.MAGIC3)
        cls = "CLASS = {}".format(self.CLASS.name)
        enc = "DATA ENCODE = {}".format(self.DATA_ENCODE.name)
        ver = "IDENT VERSION = {}({})".format(self.VERSION.value, self.VERSION.name)
        osabi = "OS ABI = {}".format(self.OSABI.name)
        abiver = "ABI VERSION = {}".format(self.ABIVER)
        return "\n".join((magic, cls, enc, ver, osabi, abiver))

class ElfHeader:
    ELF64_HDR_SIZE = 64

    def __init__(self, elfident, bindata):
        if elfident.CLASS != ElfClass.CLASS64:
            print("32bit binary is not currently supported...")
            sys.exit(1)
        if elfident.DATA_ENCODE != ElfData.LITTLE_ENDIAN:
            print("Big endian is not currently supported...")
            sys.exit(1)
        if elfident.VERSION != ElfVersion.CURRENT:
            print("This Elf version is not supported...")
            sys.exit(1)
        if elfident.OSABI != ElfOSABI.UNIX_SYSV:
            print("This OS ABI is not supported...")
            print("OS ABI =", elfident.OSABI)
            sys.exit(1)
        self.ident = elfident
        tmp = struct.unpack('HHIQQQIHHHHHH', bindata)
        self.type = self.__get_objtype(tmp[0])
        self.machine_arch = self.__get_machine_arch(tmp[1])
        self.version = get_elf_version(tmp[2])
        self.entry_addr = tmp[3]
        self.prog_hdr_offset = tmp[4]
        self.section_hdr_offset = tmp[5]
        self.flags = tmp[6]
        self.elfheader_size = tmp[7]
        self.prog_hdr_entsize = tmp[8]
        self.num_of_prog_hdr = tmp[9]
        self.section_hdr_entsize = tmp[10]
        self.num_of_section_hdr = tmp[11]
        self.shstr_index = tmp[12]

    def __get_objtype(self, code):
        return ElfObjType_reverse_lookup[code]

    def __get_machine_arch(self, code):
        return ElfMachine_reverse_lookup[code]

    def get_secheader_offset(self):
        return self.section_hdr_offset

    def get_num_of_secheader(self):
        return self.num_of_section_hdr

    def get_secheader_entsize(self):
        return self.section_hdr_entsize

    def get_shstr_index(self):
        return self.shstr_index

    def get_objtype(self):
        return self.type

    def __str__(self):
        typ = "Object Type = {}".format(self.type.name)
        machine_arch = "Machine Architecture = {}".format(self.machine_arch.name)
        version = "Version = {}({})".format(self.version.value, self.version.name)
        entry_addr = "Entry Address = 0x{:x}".format(self.entry_addr)
        prog_hdr_offset = "Offset of Program Section Header = 0x{:x} (bytes into file)" \
                            .format(self.prog_hdr_offset)
        sec_hdr_offset = "Offset of Section Header = 0x{:x} (bytes into file)" \
                            .format(self.section_hdr_offset)
        flags = "Flags = 0x{:x}".format(self.flags)
        header_size = "ELF Header Size = 0x{:x}".format(self.elfheader_size)
        prog_hdr_entsize = "Program Header Entry Size = {} (bytes)" \
                            .format(self.prog_hdr_entsize)
        num_of_prog_hdr = "The number of Program Header Entries = {}" \
                            .format(self.num_of_prog_hdr)
        sec_hdr_entsize = "Section Header Entry Size = {} (bytes)" \
                            .format(self.section_hdr_entsize)
        num_of_sec_hdr = "The number of Section Header Entries = {}" \
                            .format(self.num_of_section_hdr)
        shstr_index = "The Index of Section Header String Table = {} (index of section headers)" \
                            .format(self.shstr_index)
        return "\n".join((str(self.ident),
                      typ,
                      machine_arch,
                      version,
                      entry_addr,
                      prog_hdr_offset,
                      sec_hdr_offset,
                      flags,
                      header_size,
                      prog_hdr_entsize,
                      num_of_prog_hdr,
                      sec_hdr_entsize,
                      num_of_sec_hdr,
                      shstr_index,
                    ))


def bin2str(bindata, offset=0):
    chr_list = []
    for byte in bindata[offset:]:
        if byte == 0:
            break
        else:
            chr_list.append(chr(byte))
    return "".join(chr_list)


def bin2hexstr(bindata, offset=0):
    hexstr_list = []
    for byte in bindata[offset:]:
        hexstr_list.append("{:x}".format(byte))
    return "".join(hexstr_list)


class ElfSectionHeader:
    def __init__(self, bindata):
       tmp = struct.unpack("IIQQQQIIQQ", bindata) # support only 64bit elf section header
       self.name_index = tmp[0]
       self.type = self.__get_type(tmp[1])
       self.flags = tmp[2]
       self.vaddr_at_exe = tmp[3]
       self.file_offset = tmp[4]
       self.section_size = tmp[5]
       self.link_index = tmp[6]
       self.additional_info = tmp[7]
       self.addr_align = tmp[8]
       self.entry_size = tmp[9]
       self.section_name = ""

    def set_section_name(self, shstr_bin):
        self.section_name = bin2str(shstr_bin, self.name_index)

    def get_section_name(self):
        return self.section_name

    def __get_type(self, code):
        return ElfSectionType_reverse_lookup.get(code, code)

    def get_section_size(self):
        return self.section_size

    def get_entry_size(self):
        return self.entry_size

    def __str__(self):
        name = "Name = {}".format(self.section_name)
        name_index = "Name Index = {} (byte offsets of shstrtab)".format(self.name_index)
        typ = "Section Type = {}".format(self.type.name)
        flags = "Flags = 0x{:x}".format(self.flags)
        vaddr_at_exe = "Section Virtual Address at Execution = {}" \
                        .format(self.vaddr_at_exe)
        file_offset = "Section File Offset = 0x{:x} (bytes into file)" \
                        .format(self.file_offset)
        section_size = "Section Size = {} (bytes)".format(self.section_size)
        link_index = "Link to Another Section = {} (index of sections)" \
                        .format(self.name_index)
        additional_info = "Additional Section Info = {}".format(self.additional_info)
        align = "Section Alignment = {}".format(self.addr_align)
        entry_size = "Entry size = {} (bytes)".format(self.entry_size)
        return "\n".join((name,
                          name_index,
                          typ,
                          flags,
                          vaddr_at_exe,
                          file_offset,
                          section_size,
                          link_index,
                          additional_info,
                          align,
                          entry_size
                          ))

@unique
class ElfSymbolBinding(Enum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2
    NUM = 3
    GNU_UNIQUE = 10

ElfSymbolBinding_reverse_lookup = gen_reverse_lookup_table(ElfSymbolBinding)

@unique
class ElfSymbolType(Enum):
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    COMMON = 5
    TLS = 6
    NUM = 7
    GNU_IFUNC = 10

ElfSymbolType_reverse_lookup = gen_reverse_lookup_table(ElfSymbolType)

@unique
class ElfSymbolVisibility(Enum):
    DEFAULT = 0
    INTERNAL = 1
    HIDDEN = 2
    PROTECTED = 3

ElfSymbolVisibility_reverse_lookup = gen_reverse_lookup_table(ElfSymbolVisibility)

class ElfSymbolTableEntry:
    def __init__(self, bindata):
       tmp = struct.unpack("IBBHQQ", bindata) # support only elf64 symbol table
       self.name_index = tmp[0]
       self.info = tmp[1]
       self.other = tmp[2]
       self.section_index = tmp[3]
       self.value = tmp[4]
       self.size = tmp[5]
       self.binding = self.__get_binding()
       self.type = self.__get_type()
       self.visibility = self.__get_visibility()
       self.name = ""

    def __get_binding(self):
        return ElfSymbolBinding_reverse_lookup[self.info >> 4]

    def __get_type(self):
        return ElfSymbolType_reverse_lookup[self.info & 0xf]

    def __get_visibility(self):
        return ElfSymbolVisibility_reverse_lookup[self.other & 0x3]

    def set_symbol_str(self, bindata):
        self.name = bin2str(bindata, self.name_index)

    def get_symbol_name(self):
        return self.name

    def get_symbol_value(self):
        return self.value

    def get_type(self):
        return self.type

    def get_binding(self):
        return self.binding

    def get_size(self):
        return self.size

    def __str__(self):
        if self.name != "":
            name = "Name = {}".format(self.name)
        else:
            name = "Name = <NO NAME>"
        name_index = "Name Index = {} (string table offset in bytes)".format(self.name_index)
        info = "Symbol Type and Binding = 0x{:x}".format(self.info)
        binding = "Symbol Binding = {}".format(self.binding)
        stype = "Symbol Type = {}".format(self.type)
        other = "Other info = 0x{:x}".format(self.other)
        visibility = "Symbol Visibility = {}".format(self.visibility)
        section_index = "Index of the Related Section = {}".format(self.section_index)
        if self.section_index == 0xFFF2: # 0xFFF2 == SHN_COMMON
            symbole_value = "Aligment Constraint = 0x{}".format(self.value)
        else:
            symbol_value = "Section offset or Virtual Address = 0x{:x}".format(self.value)
        symbol_size = "Symbol Size = {}".format(self.size)
        return "\n".join((
                    name, 
                    name_index,
                    info,
                    binding,
                    stype,
                    other,
                    visibility,
                    section_index,
                    symbol_value,
                    symbol_size
                    ))

class ElfNoteType(Enum):
    GNU_ABI_TAG = 1
    GNU_HWCAP = 2
    GNU_BUILD_ID = 3
    GNU_GOLD_VERSION = 4
    GNU_PROPERTY_TYPE_0 = 5

ElfNoteType_reverse_lookup = gen_reverse_lookup_table(ElfNoteType)

class ElfNote:
    """
    Note section begins with a header of a fixed form
    """
    def __init__(self, bindata):
        tmp = struct.unpack("III", bindata[:12])
        self.name_size = tmp[0]
        self.descriptor_size = tmp[1]
        self.type = self.__get_type(tmp[2])
        self.note = bindata[12:]

    def __get_type(self, val):
        return ElfNoteType_reverse_lookup[val]

    def __str__(self):
        name_size = "Name size = {}".format(self.name_size)
        desc_size = "Descriptor size = {}".format(self.descriptor_size)
        note_type = "Note Type = {}".format(self.type)
        note_name = "Note Name = {}".format(bin2str(self.note))
        note_desc = "Note Desc = {}".format(bin2hexstr(self.note, self.name_size))
        return "\n".join((name_size, desc_size, note_type, note_name, note_desc))

class ElfInfo:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            elfheader_bin = f.read(ElfHeader.ELF64_HDR_SIZE)
            elfident = ElfIdent(elfheader_bin[:ElfIdent.ELF_IDENT_SIZE])
            self.header = ElfHeader(elfident, elfheader_bin[ElfIdent.ELF_IDENT_SIZE:])
            self.secheader_table = self.__get_secheader_table(f)
            self.symbol_dic = self.__get_symbol_dic(f)
            self.build_id = self.__get_gnu_build_id(f)

    def __get_secheader_table(self, f):
        sechdr_size = self.header.get_secheader_entsize()
        f.seek(self.header.get_secheader_offset(), 0)
        sh_list = []
        for i in range(self.header.get_num_of_secheader()):
            sh_list.append(ElfSectionHeader(f.read(sechdr_size)))
        shstr = sh_list[self.header.get_shstr_index()]
        f.seek(shstr.file_offset, 0)
        shstr_section = f.read(shstr.get_section_size())
        sh_table = {}
        for i in sh_list:
            i.set_section_name(shstr_section)
            sh_table[i.get_section_name()] = i
        return sh_table

    def __get_symbol_dic(self, f):
        symtab_hdr = self.secheader_table[".symtab"]
        f.seek(symtab_hdr.file_offset, 0)
        symtab_bin = f.read(symtab_hdr.get_section_size())
        symtab_entries = {}
        strtab_hdr = self.secheader_table[".strtab"]
        f.seek(strtab_hdr.file_offset, 0)
        strtab_bin = f.read(strtab_hdr.get_section_size())
        for i in range(symtab_hdr.get_section_size() // symtab_hdr.get_entry_size()):
            symtab_entry = ElfSymbolTableEntry(symtab_bin[i*symtab_hdr.get_entry_size():(i+1)*symtab_hdr.get_entry_size()])
            symtab_entry.set_symbol_str(strtab_bin)
            if not (symtab_entry.get_symbol_name() in symtab_entries.keys()):
                symtab_entries[symtab_entry.get_symbol_name()] = []
            symtab_entries[symtab_entry.get_symbol_name()].append(symtab_entry)
        return symtab_entries

    def __get_gnu_build_id(self, f):
        build_id_hdr = self.secheader_table[".note.gnu.build-id"]
        f.seek(build_id_hdr.file_offset, 0)
        build_id_bin = f.read(build_id_hdr.get_section_size())
        return ElfNote(build_id_bin)

    def get_symbol_by_name(self, name):
        return self.symbol_dic.get(name, False)

    def get_objtype(self):
        return self.header.get_objtype()

    def __str__(self):
        s = []
        s.append("*** ELF Header ***")
        s.append(str(self.header))
        s.append("\n*** Section Header ***")
        for v in self.secheader_table.values():
            s.append(str(v))
        s.append("\n*** Symbol Table Entries ***")
        for i in self.symbol_dic.values():
            for j in i:
                s.append(str(j))
        s.append("\n*** GNU.build-id ***")
        s.append(str(self.build_id))
        return "\n".join(s)       


def main():
    print(ElfInfo(sys.argv[1]))

if __name__ == "__main__":
    main()
