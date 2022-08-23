#! /usr/bin/env python3
"""
Embedded unwind-table generator.
"""

import io
import re
from struct import unpack_from, pack, unpack
from subprocess import Popen, PIPE, DEVNULL
import sys

U64_MAX = 0xffffffffffffffff
U32_MAX = U64_MAX >> 32

# Globals set up by the initialization routines.
WORD_SIZE = None
LP64 = None
BASE_ADDR = None

# DWARF constants used below.
DW_EH_PE_absptr	= 0x00
DW_EH_PE_omit	= 0xff
DW_EH_PE_uleb128 = 0x01
DW_EH_PE_udata2	= 0x02
DW_EH_PE_udata4	= 0x03
DW_EH_PE_udata8	= 0x04
DW_EH_PE_sleb128 = 0x09
DW_EH_PE_sdata2	= 0x0a
DW_EH_PE_sdata4	= 0x0b
DW_EH_PE_sdata8	= 0x0c
DW_EH_PE_signed	= 0x09
DW_EH_PE_pcrel	= 0x10
DW_EH_PE_indirect = 0x80
DW_EH_PE_aligned = 0x50

def encode_uleb (value):
  "Generate the byte sequence for an ULEB-128 value."
  while True:
    byte = value & 0x7f
    value >>= 7
    if value:
      byte |= 0x80
    yield byte
    if not value:
      break

def read_uleb (bx, ix):
  """
  Read an ULEB-128 from a bytes object at an offset.
  Returns the unsigned value and the number of bytes read.
  """
  ret = shift = 0
  off = ix
  while True:
    byte = bx[off]
    off += 1
    ret |= (byte & 0x7f) << shift
    if (byte & 0x80) == 0:
      break
    shift += 7

  return ret, off - ix

def read_sleb (bx, ix):
  """
  Read an SLEB-128 from a bytes object at an offset.
  Returns the signed value and the number of bytes read.
  """
  mask = [0xffffff80, 0xffffc000, 0xffe00000, 0xf0000000, 0]
  bitmask = [0x40, 0x40, 0x40, 0x40, 0x8]
  value = i = tmp = 0
  for i in range (0, 5):
    tmp = bx[ix + i] & 0x7f
    value = tmp << (i * 7) | value
    if (bx[ix + i] & 0x80) != 0x80:
      if bitmask[i] & tmp:
        value |= mask[i]
      break
  if i == 4 and (tmp & 0xf0) != 0:
    raise ValueError ("invalid sleb128")

  return unpack("i", pack ("I", value))[0], i + 1

ENCPTR_FORMATS =\
  {
    DW_EH_PE_udata2: ("=H", 2),
    DW_EH_PE_sdata2: ("=h", 2),
    DW_EH_PE_udata4: ("=I", 4),
    DW_EH_PE_sdata4: ("=i", 4),
    DW_EH_PE_udata8: ("=Q", 8),
    DW_EH_PE_sdata8: ("=q", 8)
  }

def read_encptr (bx, ix, enc, pc):
  if enc == DW_EH_PE_omit:
    return 0, 0
  elif enc == DW_EH_PE_aligned:
    size = WORD_SIZE
    new_ix = (ix + size - 1) & ~(size - 1)
    ret = unpack_from("=Q" if LP64 else "=I", bx, new_ix)[0]
    return ret, size + new_ix - ix

  xe = enc & 0x70
  if xe == DW_EH_PE_absptr:
    base = 0
  elif xe == DW_EH_PE_pcrel:
    base = pc
  else:
    raise ValueError ("unsupported pointer application value")

  if (enc & 0x7) == 0:
    enc |= DW_EH_PE_udata8 if LP64 else DW_EH_PE_udata4

  data = ENCPTR_FORMATS.get (enc & 0xf)
  if data:
    ret = unpack_from(data[0], bx, ix)[0]
    off = data[1]
  elif xe == DW_EH_PE_uleb128:
    ret, off = read_uleb (bx, ix)
  elif xe == DW_EH_PE_slen128:
    ret, off = read_sleb (bx, ix)
  else:
    raise ValueError ("unsupported data encoding")

  if ret == 0:
    # 0 is always an absolute value.
    return 0, off

  ret += base
  if (enc & DW_EH_PE_indirect) != 0:
    new_off = ret - BASE_ADDR
    ret = unpack_from("=Q" if LP64 else "=I", bx, new_off)[0]
  return ret, off


class CIE:
  def __init__ (self, dw_id):
    self.dw_id = dw_id
    self.array_idx = -1
    self.code_enc = DW_EH_PE_absptr

  def __hash__ (self):
    return hash ((self.code_align, self.ret_addr, self.data_align,
                 self.code_enc, self.opcodes))

  def __eq__ (self, x):
    return (self.code_align == x.code_align and
            self.ret_addr == x.ret_addr and
            self.data_align == x.data_align and
            self.code_enc == x.code_enc and
            self.opcodes == x.opcodes)


class Opcodes:
  """
  We try to minimize the sequence of opcodes used by both CIE's and
  FDE's by accumulating them in a hash table. This is the class that
  is hashed and stored. Unlike raw DWARF opcodes, our types have the
  size embedded in them, so knowing the end pointer is a fast operation.
  """
  def __init__ (self, bx):
    self.opcodes = bx
    self.header = list (encode_uleb (len (bx)))

  def __hash__ (self):
    return hash (self.opcodes)

  def __eq__ (self, x):
    if isinstance (x, Opcodes):
      return self.opcodes == x.opcodes
    return self.opcodes == x

  def __len__ (self):
    return len (self.opcodes) + len (self.header)


class DwarfState:
  def __init__ (self):
    self.cies_by_id = {}
    self.raw_cies = {}
    self.pc = []
    self.ops = {}
    self.ops_len = 0

  def add_opcodes (self, bx):
    ops = self.ops
    pos = ops.get (bx)
    if pos is None:
      obj = Opcodes (bx)
      ops[obj] = pos = self.ops_len
      self.ops_len += len (obj)
    return pos

  def add_cie (self, cie):
    val = self.raw_cies.get (cie)
    if val is None:
      cie.array_idx = len (self.raw_cies)
      self.raw_cies[cie] = val = cie
    self.cies_by_id[val.dw_id] = val
    cie.opcodes_idx = self.add_opcodes (cie.opcodes)

  def add_fde (self, cie, lstart, lend, opcodes):
    ops_idx = self.add_opcodes (opcodes)
    self.pc.append ((lstart, lend, cie.array_idx | (ops_idx << 16)))

  def get_cie (self, cie_id):
    return self.cies_by_id[cie_id]


def process_cie (bx, state, ix, rlen, start):
  "Add a CIE to the dwarf state."
  cie = CIE (start)
  ver = bx[ix]
  ix += 1
  aug_ix = ix
  while bx[ix] != 0:
    ix += 1

  if bx[aug_ix] == 101 and bx[aug_ix + 1] == 104:
    # Ignore GNU 'eh' augmentation data.
    ix += WORD_SIZE
    aug_ix += 2

  ix += 1
  cie.code_align, off = read_uleb (bx, ix)
  ix += off
  cie.data_align, off = read_sleb (bx, ix)
  ix += off

  if ver == 3:
    cie.ret_addr, off = read_uleb (bx, ix)
    ix += off
  else:
    cie.ret_addr = bx[ix]
    ix += 1

  istart = ix
  while True:
    ch = bx[aug_ix]
    if ch == 0:
      break
    elif ch == 122:   # 'z'
      val, off = read_uleb (bx, ix)
      ix += off
      istart = ix + val
    elif ch == 82:   # 'R'
      cie.code_enc = bx[ix]
      ix += 1

    aug_ix += 1

  cie.opcodes = bx[istart:rlen]
  state.add_cie (cie)

def process_fde (bx, state, ix, cie_id, lp64, rlen):
  "Add an FDE to the dwarf state."
  cie_id = ix - cie_id - (8 if lp64 else 4)
  cie = state.get_cie (cie_id)
  initial_loc, off = read_encptr (bx, ix, cie.code_enc, ix)
  ix += off
  addr_range, off = read_encptr (bx, ix, cie.code_enc & 0xf, ix)
  ix += off
  initial_loc += BASE_ADDR
  state.add_fde (cie, initial_loc, addr_range, bx[ix:rlen])

def process_dwarf (bx):
  """
  Given a bytes object that contains the .eh_frame section of an ELF file,
  produce a condensed view of the unwind information to be used by the
  kernel at runtime.
  """
  ix, end = (0, len (bx))
  state = DwarfState ()
  while ix < end:
    start = ix
    ulen = unpack_from("=I", bx, ix)[0]
    if ulen == 0:
      break

    ix += 4
    initlen = ulen
    lp64 = False

    if ulen == U32_MAX:
      lp64 = True
      initlen = unpack_from ("=Q", bx, ix)[0]
      ix += 8

    new_ix = ix + initlen
    if lp64:
      cie_id = unpack_from("=Q", bx, ix)[0]
      ix += 8
    else:
      cie_id = unpack_from("=I", bx, ix)[0]
      ix += 4
      if cie_id == U32_MAX:
        cie_id = U64_MAX

    if cie_id == 0:
      process_cie (bx, state, ix, new_ix, start)
    else:
      process_fde (bx, state, ix, cie_id, lp64, new_ix)

    ix = new_ix
  return state

def gen_dwarf (stdin):
  """
  Accumulate all the information from the .eh_frame section and
  return it as a bytes object. During the process, also fetch some
  data regarding base load address and others.
  """
  global BASE_ADDR
  rx = re.compile ('0x[0-9a-fA-F]* ([0-9a-fA-f]*) ' +
                   '([0-9a-fA-f]*) ([0-9a-fA-f]*) ([0-9a-fA-f]*)')
  bx = io.BytesIO ()
  for line in stdin:
    line = line.lstrip ()
    match = rx.match (line)
    if not match:
      continue
    elif BASE_ADDR is None:
      BASE_ADDR = int (line[:line.find (' ')], 16)

    for i in range (1, 5):
      try:
        val = int (match.group (i), 16)
      except ValueError:
        if not match.group (i):
          continue
        raise
      bx.write (val.to_bytes (4, byteorder = 'big', signed = False))

    bx.flush ()
  return bx.getvalue ()

def output_dwarf (state):
  # FDAs should already be sorted by address, but just in case.
  pcs = sorted (state.pc, key = lambda elem: elem[0])
  lo_pc = pcs[0][0]

  print ("#include <kern/unwind.h>\n")
  # Output CIE's.
  print ("static const struct unw_cie unw_cies[] __unwind =\n{\n", end = "")
  for cie in state.raw_cies:
    print ("  { 0x%x, 0x%x, %d, %d, %d },\n" % (cie.code_align, cie.ret_addr,
                                                cie.data_align, cie.code_enc,
                                                cie.opcodes_idx),
           end = "")
  print ("};\n\n", end = "")

  # Output FDE's.
  print ("static const struct unw_fde unw_fdes[] __unwind =\n{\n", end = "")
  for pc in pcs:
    print ("  { 0x%x, 0x%x, 0x%x },\n" % (pc[0] - lo_pc, pc[1], pc[2]),
           end = "")
  print ("};\n\n", end = "")

  # Output opcodes shared by both CIE's and FDE's.
  i = 0
  print ("static const uint8_t unw_opcodes[] __unwind =\n{", end = "")
  for op in state.ops:
    for byte in op.header:
      if (i & 7) == 0:
        print ("\n  ", end = "")
      print ("0x%02x, " % byte, end = "")
      i += 1
    for byte in op.opcodes:
      if (i & 7) == 0:
        print ("\n  ", end = "")
      print ("0x%02x, " % byte, end = "")
      i += 1

  print ("\n};\n")

  # Output global data.
  print ("const struct unw_globals unw_globals __unwind =\n{")
  print ("  .nr_fdes = %d,\n" % len (state.pc), end = "")
  print ("  .fdes = unw_fdes,\n", end = "")
  print ("  .cies = unw_cies,\n", end = "")
  print ("  .ops = unw_opcodes,\n", end = "")
  print ("  .base_addr = 0x%xul\n" % lo_pc, end = "")
  print ("};\n")

  print ("const struct unw_globals *unw_globals_ptr = &unw_globals;\n")

def main (path):
  global LP64, WORD_SIZE
  with Popen (["readelf", "-h", "-x", ".eh_frame", path],
              stdout = PIPE, stderr = DEVNULL, text = True) as proc:
    stdin = proc.stdout
    for line in stdin:
      if line.find ("Class") >= 0:
        LP64 = line.find ("ELF64") >= 0
        WORD_SIZE = 8 if LP64 else 4
        break
    else:
      raise ValueError ("could not find ELF class in file")

    rv = process_dwarf (gen_dwarf (stdin))
    output_dwarf (rv)

if __name__ == "__main__":
  main (sys.argv[1])
