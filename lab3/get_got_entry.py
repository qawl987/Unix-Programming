from pwn import *
elf = ELF('./gotoku')
# print("main =", hex(elf.symbols['main']))
# print("{:<12s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset"))
# for s in [ f"gop_{i+1}" for i in range(1200)]:
#    if s in elf.got:
#       print("{:<12s} {:<10x} {:<10x}".format(s, elf.got[s], elf.symbols[s]))
print("main =", hex(elf.symbols['main']))
for s in [ f"gop_{i+1}" for i in range(1200)]:
   if s in elf.got:
      print("{},".format(elf.got[s]))