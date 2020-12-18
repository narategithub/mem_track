#!/usr/bin/python3

import os
import re
import sys
import mmap
import struct
import argparse as ap
import subprocess as sp

from collections import namedtuple

if __name__ != "__main__":
    raise ImportError("Not a module!")

p = ap.ArgumentParser(description = "Print memory tracking results from a mem track file")
p.add_argument("MEM_TRACK", nargs=1, help="The memory track file.")
p.add_argument("--map", "-m",
               help="The map file (to convert caller ptr to symbols")

args = p.parse_args()

MemTrackEntry = namedtuple("MemTrackEntry", ["ptr", "sz", "caller"])
Ent = struct.Struct("PNP")
PTR = 0
SZ = 1
CALLER = 2

class Debug(object): pass
D = Debug()

class SymbolTable(object):
    RE = re.compile(r"""
            (?P<addr>[0-9a-f]+)\s+
            (?P<type>.)\s+
            (?P<sym>.*)
        """, flags = re.VERBOSE) # ignore weak and undefined symbols
    def __init__(self, path):
        self.tbl = dict()
        self.path = path
        self.load(path)

    def load(self, path):
        try:
            cmd = "nm -a {} 2>&1".format(path)
            out = sp.check_output(cmd, shell=True)
        except:
            return
        for l in out.splitlines():
            m = self.RE.match(l.decode())
            if not m:
                continue # skip weak and undefined symbols
            addr, typ, sym = m.groups()
            self.tbl[int(addr, base=16)] = (typ, sym)

    def get_symbol(self, addr):
        rec = self.tbl.get(addr)
        if not rec:
            return "{}+{:#x}".format(self.path, addr)
        return "{}:{}()".format(self.path, rec[1])


BEGIN = 0
END = 1
OFFSET = 2
PATH = 3
class MemoryMap(object):
    RE = re.compile(r"""
            (?P<begin>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+
            (?P<perm>....)\s+
            (?P<offset>[0-9a-f]+)\s+
            (?P<dev>\S+)\s+
            (?P<inode>[0-9a-f]+)\s+
            (?P<path>.*)$
        """, flags = re.VERBOSE)

    def __init__(self, path):
        self.path = path
        self.records = list()
        self.symtbl = dict() # symbol table by path
        # special case
        rec = (0, 0, 0, "[main]")
        self.records.append(rec)
        self.load(path)

    def load(self, path):
        f = open(path, "r")
        for l in f:
            m = self.RE.match(l)
            if not m:
                raise ValueError("Bad format: {}".format(l))
            d = m.groupdict()
            begin = int(d["begin"], base=16)
            end = int(d["end"], base=16)
            offset = int(d["offset"], base=16)
            rec = (begin, end, offset, d["path"])
            self.records.append(rec)
        self.records.sort()
        for bgn, end, off, path in self.records:
            if not path.startswith("/"):
                continue
            tbl = self.symtbl.get(path)
            if tbl:
                continue
            tbl = SymbolTable(path)
            self.symtbl[path] = tbl

    def find_rec(self, addr):
        l = 0
        r = len(self.records)-1
        while l <= r:
            c = (l+r)//2
            rec = self.records[c]
            if addr < rec[BEGIN]:
                r = c - 1
                continue
            if rec[END] < addr:
                l = c + 1
                continue
            return rec
        return None

    def get_symbol(self, addr):
        rec = self.find_rec(addr)
        lib_off = addr - rec[BEGIN] + rec[OFFSET]
        if not rec[PATH].startswith("/"):
            return "{}+{:#x}".format(rec[PATH], lib_off)
        tbl = self.symtbl[rec[PATH]]
        return tbl.get_symbol(lib_off)


mp = MemoryMap(args.map) if args.map else None

f = open(args.MEM_TRACK[0], "rb")
mt = mmap.mmap(f.fileno(), 0, mmap.MAP_SHARED,
                              mmap.PROT_READ|mmap.PROT_WRITE,
                              mmap.ACCESS_READ|mmap.ACCESS_WRITE)

mem_tracks = dict() # track memory by caller
for off in range(0, len(mt), Ent.size ):
    data = mt[ off : off + Ent.size ]
    x = Ent.unpack(data)
    if not x[PTR]:
        continue # unallocated entry
    s = mem_tracks.setdefault(x[CALLER], list())
    s.append(x)
for c, l in mem_tracks.items():
    print("caller:", mp.get_symbol(c))
    print("  entries:", len(l))
    _sum = 0
    for x in l:
        _sum += x[SZ]
    print("  total bytes:", _sum)
