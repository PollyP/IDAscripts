##########################################################################################################
# ida_instrumented_breakpoints.py
#
# as configured breakpoint addresses are hit, interrogate specified registries/stack items and print
# out their values.
#
# based on the IDA pro debug hook example script written by Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# to modify for your use, create a BptDump class and add it to allbreakpointsl. see the "configure
# breakpoints action here" section for an example.
#
# License: do what thou will.
#
##########################################################################################################

from idc import *
from idaapi import *

##########################################################################################################
# helper classes
##########################################################################################################

STRINGP = 1
INTP = 2
INT  = 3


class RegItem:
	# this class interrogates a configured register. it takes a string representation of
	# a register, a type parameter, and a label to print
	# the type parameter can be an INT or a STRINGP.
	def __init__(self,reg,type=STRINGP,label=""):
		self.reg = reg
		self.type = type
		self.label = label
	def __str__(self):
		v = idc.GetRegValue(self.reg)
		if self.type == STRINGP:
			val = GetString(v, 10, ASCSTR_C)
			return "%s:%s: val:%s" % (self.label,self.reg,val)
		elif self.type == INT:
			return "%s:%s: val:0x%x (%d)" % (self.label,self.reg,v,v)

class StackVarItem:
	# this class interrogates a configured stack address. it takes a possibly-signed
	# offset value, a type parameter, and a label to print
	# the type parameter can be an INT or a STRINGP.
	def __init__(self,sa,type=STRINGP,label=""):
		self.sa = sa
		self.type = type
		self.label = label
	def __str__(self):
		ebp = GetRegValue("EBP")
		addr = ebp + self.sa
		if self.type == STRINGP:
			val = GetString(addr, 10, ASCSTR_C)
			return "%s:ebp+%s: val:%s" % (self.label,str(self.sa),val)
		elif self.type == INT:
			val = Dword(addr)
			return "%s:ebp+%s: val:0x%x (%d)" % (self.label,str(self.sa),val,val)		


class BptDump:
	# this class takes an address, a string label to print when you hit that
	# address, and a dictionary of registers and/or stack values to interrogate
	# when that address is hit.
	# this dictionary can have: 
	#	- a key of 'reges', and a value of a list of RegItems, and/or
	#	- a key of 'stackoffsets', and a value of a list of StackVarItems
	def __init__(self,ea,ealabel="",dumpdict={}):
		self.ea = ea
		self.ealabel = ealabel
		self.dumpdict = dumpdict

	def mydump(self):
		if self.ealabel != "": print("%s" % self.ealabel)
		if self.dumpdict.has_key("stackoffsets"):
			for lv in self.dumpdict["stackoffsets"]:
				print("\t%s" % str(lv))

		if self.dumpdict.has_key("reges"):
			for r in self.dumpdict["reges"]:
				print("\t%s" % str(r))
##########################################################################################################
# configure breakpoint actions here
##########################################################################################################

# first instrumented address
opsv1 = StackVarItem(+0x8,INT,"pid")
opr1 = RegItem("EAX",INT,"returned process handle")
openprocess = BptDump(0x40107E, "openprocess", {'reges':[opr1], 'stackoffsets':[opsv1]} )


# second instrumented address
strcmpr1 = RegItem("EAX",STRINGP,"string1")
strcmplv1 = StackVarItem(-0x118,STRINGP,"string2")
strcmp1 = BptDump(0x4010CD, "basemodulestrcmpy", {'reges':[strcmpr1], 'stackoffsets':[strcmplv1]} )


#allbreakpointsl = [openprocess,strcmp1]
allbreakpointsl = [openprocess]
#allbreakpoints = dict( [ (b.ea,b) for b in allbreakpointsl ] )


##########################################################################################################
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Original Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# Maintained By: IDAPython Team
##########################################################################################################


class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

    def dbg_library_unload(self, pid, tid, ea, info):
        print("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
        return 0

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))

    def dbg_process_detach(self, pid, tid, ea):
        print("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)

    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)

	idaapi.refresh_debugger_memory()

	if ea in allbreakpoints.keys():
		allbreakpoints[ea].mydump()

        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.

	idaapi.continue_process()
        return 0

    def dbg_suspend_process(self):
        print "Process suspended"

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        print("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
        # return values:
        #   -1 - to display an exception warning dialog
        #        if the process is suspended.
        #   0  - to never display an exception warning dialog.
        #   1  - to always display an exception warning dialog.
        return 0

    def dbg_trace(self, tid, ea):
        print("Trace tid=%d ea=0x%x" % (tid, ea))
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        return 0

    def dbg_step_into(self):
        print("Step into")
        self.dbg_step_over()

    def dbg_run_to(self, pid, tid=0, ea=0):
        print "Runto: tid=%d" % tid
        idaapi.continue_process()


    def dbg_step_over(self):
        eip = GetRegValue("EIP")
        print("0x%x %s" % (eip, GetDisasm(eip)))
	request_step_over()

        #self.steps += 1
        #if self.steps >= 5:
        #    request_exit_process()
        #else:
        #    request_step_over()


# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# install breakpoints. if the installation returns
# false, we don't care; that means the breakpoints already exist
allbreakpoints = dict( [ (b.ea,b) for b in allbreakpointsl ] )
for e in allbreakpoints.keys():
	if idc.AddBpt(e) == True:

		print("installed breakpont")
	else:
		print("breakpoint already exists")

# Stop at the entry point
ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

# Step one instruction
request_step_over()

# Start debugging
run_requests()


