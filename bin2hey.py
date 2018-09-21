import sys
import binascii

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print ("usage: %s file.bin\n" % (sys.argv[0],) )
        sys.exit(0)

    shellcode = "unsigned char shellcode[] =\n"
    shellcode += "\""
    ctr = 1
    maxlen = 15
    
    for b in open(sys.argv[1], "rb").read():
        shellcode += "\\x" + '{:02x}'.format(b) 
        if ctr == maxlen:
            shellcode += "\"\n\""
            ctr = 0
        ctr += 1
	
    shellcode += "\";"
print (shellcode)
