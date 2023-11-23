from pwn import *
from binaryninja import load
from binaryninja.debugger import DebuggerController
from librondo import BinjaDBG
context.binary = elf = ELF("./error")

bv = load(elf.path)
dbg = DebuggerController(bv)
bdbg = BinjaDBG(elf.path)
for x in range(20):
    io = elf.process()

    # bdbg.attach(io.pid)
    dbg.pid_attach = io.pid
    dbg.attach_and_wait()

    dbg.go()

    io.sendline(b"A")

    io.interactive()