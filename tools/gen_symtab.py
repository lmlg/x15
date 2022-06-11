#!/usr/bin/env python3
'''
Embedded symbol table generator.
'''

import sys

symtab = []

def valid_symbol (parts):
  if len (parts) != 4:
    return False

  sym = parts[3]
  if (sym.startswith ("__func__") or sym.startswith ("CSWTCH") or
      (parts[2] == 'r' and sym.startswith ("symbol_name_"))):
    return False

  del parts[2]
  return True

for line in sys.stdin:
  line = line.strip ()
  parts = line.split (' ')

  if not valid_symbol (parts):
    continue

  sym = {'addr': parts[0], 'size': parts[1], 'name': parts[2]}
  symtab.append (sym)

print ("#include <kern/symbol.h>")

for index, sym in enumerate (symtab):
  print ("static const char symbol_name_%u[] __symbol_table = \"%s\";" %
    (index, sym['name']))

print ("const struct symbol symbol_table[] __symbol_table = {")

for index, sym in enumerate (symtab):
  print ("    { 0x%s, 0x%s, symbol_name_%u }," %
    (sym['addr'], sym['size'], index))

print ("};")
print ("const size_t symbol_table_size = %d;" % len (symtab))
print ("const struct symbol *symbol_table_ptr = symbol_table;")
