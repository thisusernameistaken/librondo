from binaryninja import load as bv_load
from binaryninja.debugger import (
    DebuggerController,
    DebuggerEvent,
    ModuleNameAndOffset,
    DebuggerEventWrapper,
    DebugStopReason
)
from pyRpc import RpcConnection
import time
import pwnlib
from pwn import *

class Rctx:
    active_dbg = None

rcontext = Rctx()

class Hook:
    def __init__(self,callback):
        self.callback = callback
        self.hit_count = 0
        self.enabled = True

def hook_addr(event):
    if event.data.target_stopped_data.reason == DebugStopReason.Breakpoint:
        hooks = rcontext.active_dbg.hooks
        current_ip = rcontext.active_dbg.dc.ip
        if current_ip in hooks.keys():
            hook = hooks[current_ip]
            # if hook.enabled:
                # hook.enabled=False
            hook.hit_count+=1
            hook.callback(rcontext.active_dbg)
                # hook.enabled=True
            
            

class BinjaDBG:

    def __init__(self,path):
        self.bv = bv_load(path,options={"analysis.mode":"controlFlow"})
        self.dc = DebuggerController(self.bv)
        self.hooks = {}
        self.hook_events = []


    def attach(self,pid):
        for event in self.hook_events:
            self.dc.remove_event_callback(event)
        self.hook_events = []
        rcontext.active_dbg = self
        self.hooks = {}
        self.dc.pid_attach = pid
        self.dc.attach_and_wait()
        

    def hook(self,addr,callback):
        # if isinstance(addr,ModuleNameAndOffset):
        #     addr_str = f"{addr.module}+{hex(addr.offset)}"
        #     addr = self.dc.data.
        # else:
        #     addr_str = hex(addr)
        if addr not in self.hooks.keys():
            self.dc.add_breakpoint(addr)
            # DebuggerEventWrapper.register(self.dc,hook_addr,"hook_"+hex(addr))
            self.hook_events.append(self.dc.register_event_callback(hook_addr,"hook_"+hex(addr)))
        self.hooks[addr]=Hook(callback)

    def go(self):
        # self.dc.execute_backend_command("continue")
        self.dc.go()

    def step_return(self):
        hit = False
        while not hit and self.dc.connected:
            self.dc.step_over_and_wait()
            dis = self.dc.data.get_disassembly(self.dc.ip)
            if dis.startswith('ret'):
                hit = True

    def call(self,address,args=[]):
        arg_regs = self.dc.data.arch.calling_conventions['sysv'].int_arg_regs
        for i,arg in enumerate(args):
            self.dc.regs[arg_regs[i]]=arg       

        self.dc.regs['rsp'].value-=8
        next_instr = self.dc.ip + self.dc.data.get_instruction_length(self.dc.ip)
        self.dc.live_view.writer().write64le(next_instr,self.dc.stack_pointer)
        self.dc.ip = address
        self.step_return()
        try:
            return self.dc.regs['rax'].value
        except:
            return None

class DBGServiceException(Exception):
    "Can not connect to binja dbg service"
    pass

def ui_attach(x):
    remote = RpcConnection("com.rondo.binjadbg")
    time.sleep(.1)

    if remote is None:
        raise DBGServiceException
    # we can ask the remote server what services are available
    if isinstance(x,int):
        remote.call("attach",args=(x,))
    elif isinstance(x,pwnlib.tubes.process.process):
        remote.call("attach",args=(x.pid,))
    else:
        raise DBGServiceException("Invalid Argument")
    time.sleep(1)
