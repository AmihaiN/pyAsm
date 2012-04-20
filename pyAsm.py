import subprocess
import os
from ctypes import *
import struct
import time

'''
TODO - use some exceptions!!

'''
END  = 0
START  = 1
THREAD_START_SIGNAL = 0x000000000
THREAD_FIN_SIGNAL        = 0x000000001

A_16BIT = 16
A_32BIT = 32
A_64BIT = 64
SUPPORTED_ARCH = [A_16BIT,A_32BIT,A_64BIT]

class FLOATING_SAVE_AREA(Structure):
   _fields_ = [ 
        ("ControlWord", c_ulong),
        ("StatusWord", c_ulong),
        ("TagWord", c_ulong),
        ("ErrorOffset", c_ulong),
        ("ErrorSelector", c_ulong),
        ("DataOffset", c_ulong),
        ("DataSelector", c_ulong),
        ("RegisterArea", c_ubyte * 80),
        ("Cr0NpxState", c_ulong),
]

class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", c_ulong),
        ("Dr0", c_ulong),
        ("Dr1", c_ulong),
        ("Dr2", c_ulong),
        ("Dr3", c_ulong),
        ("Dr6", c_ulong),
        ("Dr7", c_ulong),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", c_ulong),
        ("SegFs", c_ulong),
        ("SegEs", c_ulong),
        ("SegDs", c_ulong),
        ("Edi", c_ulong),
        ("Esi", c_ulong),
        ("Ebx", c_ulong),
        ("Edx", c_ulong),
        ("Ecx", c_ulong),
        ("Eax", c_ulong),
        ("Ebp", c_ulong),
        ("Eip", c_ulong),
        ("SegCs", c_ulong),
        ("EFlags", c_ulong),
        ("Esp", c_ulong),
        ("SegSs", c_ulong),
        ("ExtendedRegisters", c_ubyte * 512),
]

class pyAsm():
	def __init__(self,Arch):
		self._NASM = r'Z:\pyAsm\nasm.exe'
		self._ASM_STR = '' #The code
		self._ARCH = Arch
		
	def update(self,s,Location = END):
		if s != None:
			if Location == START:
				self._ASM_STR = (s+'\n')	+ self._ASM_STR
			elif Location == END:
				self._ASM_STR += (s+'\n')	
		
	def run(self):
		'''
			Assemble the given NASM code,place it in memory and execute it using a new thread!
		'''
		CONTEXT_FULL = 0x00010007
		CONTEXT_DEBUG_REGISTERS = 0x00010010
		THREAD_ALL_ACCESS   = 0x001F03FF

		bytes,SignalAddress = self._assemble()
		if bytes is not None and SignalAddress is not None:
			Flag = (c_int*1).from_address(SignalAddress)
			ptr = self._PlaceDataInMemory(bytes)
			if ptr ==0:
				return None
				
			thread_id = c_ulong(0)
			h_thread = windll.kernel32.CreateThread(None,0,ptr,None,0,byref(thread_id))
			windll.kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
			
			while(Flag[0] != THREAD_FIN_SIGNAL):
				time.sleep(0)
					
			context = CONTEXT()
			context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
			windll.kernel32.GetThreadContext(h_thread, byref(context))
			windll.kernel32.TerminateThread(h_thread,1)
			return context
		else:
			pass
	
	def _addClosure(self):
		HEAP_ZERO_MEMORY = 0x00000008
		
		hHeap = windll.kernel32.GetProcessHeap()
		ptrHeap = windll.kernel32.HeapAlloc(hHeap,HEAP_ZERO_MEMORY,1)
		
		#We'll loop ourself 'till we get suspended
		self.update('mov dword [' + hex(ptrHeap) + '],' + hex(THREAD_START_SIGNAL),START) #Set flag to 0 - Start
		self.update('__LP__:')
		self.update('mov dword [' + hex(ptrHeap) + '],' + hex(THREAD_FIN_SIGNAL))     #Set flag to 1 - End
		self.update('jmp __LP__')
		#maybe more? .. collect the data maybe... mmm do some rethink
		
		if self._ARCH in SUPPORTED_ARCH:
			if self._ARCH == A_16BIT:
				self.update('USE16',START)
			elif self._ARCH == A_32BIT:
				self.update('USE32',START)
			elif self._ARCH == A_64BIT:
				self.update('USE64',START)
		
		return ptrHeap
		
	def _assemble(self):
		tempCode = self._ASM_STR
		SiganlAddress = self._addClosure()
		
		#for now we will use drop files. in the near future I will try to replace it with named pipes
		tmpIFile = '~pyAsm.asm'
		tmpOFile = '~o.out'
		
		if self._createIFile(tmpIFile):
			if subprocess.call([self._NASM,'-f','bin',tmpIFile,'-o',tmpOFile]) == 0:
				data = open(tmpOFile).read()
				#cleanup
				os.remove(tmpIFile)
				os.remove(tmpOFile)
				self._ASM_STR = tempCode
				return (data,SiganlAddress)
		self._ASM_STR = tempCode
		return (None,None)
	
	def _createIFile(self,file):
		f = open(file,'w')
		if f is not None:
			f.write(self._ASM_STR)
			f.close()
			return True
		return False

	def _PlaceDataInMemory(self,data,BaseAddress = 0x400000):
		MEM_COMMIT = 0x1000
		PAGE_EXECUTE_READWRITE = 0x40
		
		baseAddr = BaseAddress
		ptr = 0
		while ptr == 0:
			ptr = windll.kernel32.VirtualAlloc(baseAddr,len(data)*2,MEM_COMMIT,PAGE_EXECUTE_READWRITE)
			baseAddr = baseAddr + 2**16 #2^16 = 64k, the min allocation ... I forgot the term :P
		p = (c_char*len(data)).from_address(ptr) 
		for i in range(0,len(data)):
			p[i] = data[i]
		
		return ptr