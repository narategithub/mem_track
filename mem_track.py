#!/usr/bin/python3

import os
import re
import pdb
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
p.add_argument("--no-lseek", "-L", action="store_true", default = False,
               help="Enforce no lseek (default: auto / lseek preferred)")

args = p.parse_args()

print("cmd: ", " ".join(sys.argv))

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
        if not rec:
            return "{:#x}".format(addr)
        lib_off = addr - rec[BEGIN] + rec[OFFSET]
        if not rec[PATH].startswith("/"):
            return "{}+{:#x}".format(rec[PATH], lib_off)
        tbl = self.symtbl[rec[PATH]]
        return tbl.get_symbol(lib_off)

class MemTrack(object):
    def __init__(self, path, no_lseek = False):
        self.fd = os.open(path, os.O_RDONLY)
        self.mt = mmap.mmap(self.fd, 0, mmap.MAP_SHARED, mmap.PROT_READ)
        # test if lseek works
        try:
            if no_lseek:
                raise Exception("no lseek") # handle below
            pos = os.lseek(self.fd, 0, os.SEEK_DATA)
            print("use lseek")
            self.can_lseek = True
        except:
            print("no lseek")
            self.can_lseek = False

    def load(self):
        mem_tracks = dict()
        for x in self.rec_iter():
            s = mem_tracks.setdefault(x[CALLER], list())
            s.append(x)
        self.mem_tracks = mem_tracks

    def rec_iter_mmap(self):
        for pos in range(0, len(self.mt), Ent.size):
            data = self.mt[ pos : pos + Ent.size ]
            x = Ent.unpack(data)
            if not x[PTR]:
                continue # unallocated entry
            yield x
        pass

    def rec_iter_lseek(self):
        # rely on lseek to skip HOLE
        pos = 0
        while pos < len(self.mt):
            try:
                data_pos = os.lseek(self.fd, pos, os.SEEK_DATA)
            except:
                data_pos = len(self.mt)
            try:
                hole_pos = os.lseek(self.fd, data_pos, os.SEEK_HOLE)
            except:
                hole_pos = len(self.mt)
            pos = data_pos + (data_pos % Ent.size)
            while pos < hole_pos:
                data = self.mt[ pos : pos + Ent.size ]
                pos += Ent.size
                x = Ent.unpack(data)
                if not x[PTR]:
                    continue # unallocated entry
                yield x

    def rec_iter(self):
        return self.rec_iter_lseek() if self.can_lseek else self.rec_iter_mmap()


mp = MemoryMap(args.map) if args.map else None

mt = MemTrack(args.MEM_TRACK[0], args.no_lseek)
mt.load()

callers = list(mt.mem_tracks.keys())
callers.sort()
for c in callers:
    l = mt.mem_tracks[c]
    print("caller:", mp.get_symbol(c) if mp else hex(c))
    print("  entries:", len(l))
    _sum = 0
    for x in l:
        _sum += x[SZ]
    print("  total bytes:", _sum)
