from binaryninja.plugin import (
    BackgroundTaskThread,
    PluginCommand
)
from binaryninja.debugger import DebuggerController
import time
from pyRpc import PyRpc

global_bv = None

def attach(pid):
    global global_bv
    print("Attaching to pid:",pid,global_bv)
    dbg = DebuggerController(global_bv)
    dbg.pid_attach=pid
    dbg.attach_and_wait()
    print("dbg launched")

class RPCService(BackgroundTaskThread):

    def __init__(self,bv):
        BackgroundTaskThread.__init__(self,"Running dbg service",True)
        self.bv = bv

    def run(self):
        print("Starting")
        myRpc = PyRpc("com.rondo.binjadbg") 
        time.sleep(.1)

        myRpc.publishService(attach)
        myRpc.start()

        while True:
            time.sleep(1)



    # def cancel(self):
    #     self.progress=""

def runService(bv):
    global global_bv
    global_bv = bv
    s = RPCService(bv)
    s.start()

PluginCommand.register("BinjaDBG Service","Start BinjaDBG Service",runService)