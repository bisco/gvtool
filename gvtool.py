#!/usr/bin/env python3

import sys, os
import re
import subprocess
import struct

import pet

DEBUG = False

class ProcMapEntry:
    def __init__(self, start, end, permission, offset, dev, inode, path):
        self.start_addr = int(start, 16)
        self.end_addr = int(end, 16)
        self.permission = permission
        self.__parse_perm(permission)
        self.offset = int(offset, 16)
        self.dev = dev
        self.inode = inode
        if path != False:
            self.path = path
        else:
            self.path = self.__gen_path()

    def __gen_path(self):
        return "blank_0x{:x}-0x{:x}".format(self.start_addr, self.end_addr)

    def __parse_perm(self, permission):
        if permission[0] == "r":
            self.read = True
        else:
            self.read = False
        if permission[1] == "w":
            self.write = True
        else:
            self.write = False
        if permission[2] == "x":
            self.exe = True
        else:
            self.exe = False
        if permission[3] == "p":
            self.private = True
        else:
            self.private = False

    def get_path(self):
        return self.path

    def get_offset(self):
        return self.offset

    def get_start_addr(self):
        return self.start_addr

    def __str__(self):
        return "{} 0x{:x}-0x{:x} {} 0x{:x}".format(self.path,
                                                   self.start_addr,
                                                   self.end_addr,
                                                   self.permission,
                                                   self.offset)

class ProcMaps:
    def __init__(self, pid):
        self.pid = pid
        self.map_entries = {}

    def add_entry(self, entry):
        if self.map_entries.get(entry.get_path(), False) == False:
            self.map_entries[entry.get_path()] = []
        self.map_entries[entry.get_path()].append(entry)

    def get_all_path(self):
        return self.map_entries.keys()

    def get_entries(self, key):
        return self.map_entries[key]

def get_baseaddr(filepath, pid):
    p = ProcMaps(pid)
    with open("/proc/{}/maps".format(pid), "r") as f:
        for line in f:
            entry = re.sub(r" +", r" ", line.strip()).split(" ")
            if entry[-1] == "[stack]" or entry[-1] == "[vdso]" or entry[-1] == "[vvar]":
                pass
            if DEBUG:
                print(entry)
            addr = entry[0].split("-")
            perm = entry[1]
            offset = entry[2]
            dev = entry[3]
            inode = entry[4]
            if entry[-1] == "0":
                path = False
            else:
                path = entry[5]
            p.add_entry(ProcMapEntry(addr[0], addr[1], perm, offset, dev, inode, path))

    ret = 0xFFFFFFFFFFFFFFFF
    for e in p.get_entries(filepath):
        if e.get_offset() == 0:
            tmp = e.get_start_addr()
            if tmp < ret:
                ret = tmp
                if DEBUG:
                    print("start_addr: 0x{:x}".format(ret))
    return ret

def procmem_getfd(pid):
    fd = os.open("/proc/{}/mem".format(pid), os.O_RDWR)
    return fd

def procmem_closefd(fd):
    os.close(fd)

def get_pack_str(length):
    if length == 1:
        return "@c"
    elif length == 2:
        return "@H"
    elif length == 4:
        return "@I"
    elif length == 8:
        return "@Q"
    else:
        print("length == {} is not supported".format(length))
        sys.exit(1)

def procmem_read(fd, base_addr, offset, size):
    unpack_str = get_pack_str(size)
    acc_addr = base_addr + offset
    result = struct.unpack(unpack_str, os.pread(fd, size, acc_addr))[0]
    return result

def procmem_write(fd, base_addr, offset, write_data, size):
    pack_str = get_pack_str(size)
    acc_addr = base_addr + offset
    os.pwrite(fd, struct.pack(pack_str, write_data), acc_addr)

def main():
    pyver_major = sys.version_info.major
    pyver_minor = sys.version_info.minor
    if not (pyver_major >= 3 and pyver_minor >= 3):
        print("please use python3.3 or later...")
        sys.exit(1)

    if len(sys.argv) < 4:
        print("usage: ./gvtool.py </path/to/elfbinary> <PID> <GLOBAL_VARIABLE_NAME> {<WRITE_VALUE>}")
        sys.exit(1)

    # parse args
    filepath = os.path.abspath(sys.argv[1])
    pid = int(sys.argv[2].strip())
    gvar_name = sys.argv[3].strip()
    if len(sys.argv) == 5:
        if sys.argv[4].find("0x") == 0:
            write_value = int(sys.argv[4], 16)
        elif sys.argv[4].find("0o") == 0:
            write_value = int(sys.argv[4], 8)
        else:
            write_value = int(sys.argv[4])
    else:
        write_value = None

    # read elf info
    elfinfo = pet.ElfInfo(filepath)
    objtype = elfinfo.get_objtype()
    if DEBUG:
        print("objtype: {}".format(objtype))
    if objtype  == pet.ElfObjType.DYN:
        base_addr = get_baseaddr(filepath, pid)
    elif objtype == pet.ElfObjType.EXEC:
        base_addr = 0
    else:
        print("please input DYN or EXEC type ELF binary")
        sys.exit(1)
    if DEBUG:
        print("base_addr: 0x{:x}".format(base_addr))

    symbol_entries = elfinfo.get_symbol_by_name(gvar_name)
    for i, s in enumerate(symbol_entries):
        if s.get_type() == pet.ElfSymbolType.OBJECT and \
           s.get_binding() == pet.ElfSymbolBinding.GLOBAL:
            symbol_info = symbol_entries[i]

    if symbol_info == None:
        print("There is no symbol info...")
        sys.exit(1)

    offset = symbol_info.get_symbol_value()
    size = symbol_info.get_size()
    if DEBUG:
        print("offset: 0x{:x}".format(offset))
    if offset == False:
        print("ERROR: no such global variable")
        sys.exit(1)

    fd = procmem_getfd(pid)
    if write_value == None:
        result = procmem_read(fd, base_addr, offset, size)
        print("{} = 0x{:X}".format(gvar_name, result))
    if write_value != None:
        result = procmem_read(fd, base_addr, offset, size)
        print("before: {} = 0x{:X}".format(gvar_name, result))
        procmem_write(fd, base_addr, offset, write_value, size)
        result = procmem_read(fd, base_addr, offset, size)
        print("after: {} = 0x{:X}".format(gvar_name, result))
    procmem_closefd(fd) 

if __name__ == "__main__":
    main()
