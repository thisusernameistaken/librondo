from pwn import *
from librondo import BinjaDBG
import string
import logging
logging.getLogger("pwnlib.tubes.process.process").setLevel(logging.WARNING)

context.binary = elf = ELF("./error")

def check_call(dbg):
    next_instr = dbg.dc.ip + dbg.dc.data.get_instruction_length(dbg.dc.ip)
    dbg.dc.ip = next_instr
    dbg.call(dbg.dc.data.get_symbol_by_raw_name("check").address,[dbg.dc.regs['rax'].value])
    dbg.go()

bdbg = BinjaDBG(elf.path)
flag = b"ictf"
for x in range(0x2c):
    for char in "{}_I"+string.ascii_lowercase:
        test = flag + char.encode()
        io = elf.process()
        bdbg.attach(io.pid)
        
        raise_call = bdbg.dc.data.start+0x1207
        bdbg.hook(raise_call,check_call)
        bdbg.go()
        io.sendline(test)
        
        io.recvall(timeout=5)
        if bdbg.hooks[raise_call].hit_count-1 > len(flag):
            flag = test
            print(flag)
            break
        __import__("time").sleep(0.1)