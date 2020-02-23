#!/usr/bin/python
#arg_parse.py
#coding:utf-8
import argparse
import cle
from capstone import *
import argparse
import os
import sys
def binary_loaded_info(app_bin):
    
    # First, get binary type: executable or shared object(PIE)
    bin_type = "executable"
    app_bin = os.path.realpath(app_bin)
    file_info = os.popen("file " + app_bin)
    sstr = file_info.read()
    print "file info: ", sstr

    if "shared object" in sstr:
        bin_type = "shared_object"
    print "binary type is ", bin_type
    raw_bin = "." + os.path.basename(app_bin) + ".text"

    # Now load binary, calculate program loaded base, entry, text_min and text_max 
    ld = cle.Loader(app_bin)
    bin_code = None
        
    base_addr = ld.main_object.sections[0].vaddr
    entry = ld.main_object.entry
    print "Program base by cle: ", hex(base_addr)
    print "Program entry by cle: ", hex(entry)
    for i in ld.main_object.sections:
        if i.name == ".text":
            text_min = i.vaddr
            text_max = i.vaddr + i.filesize
            if os.path.isfile(raw_bin):
                if os.path.getsize(raw_bin) == i.filesize:
                    print raw_bin, " exists, if you want to regenerate it, just delete this file."
                    break;
            print "reading .text code..."
            raw_bytes = ld.memory.read_bytes(i.vaddr, i.filesize)
            bin_code = ""
            for byte in raw_bytes:
                bin_code += byte
            break
        
    #Third, write raw binary code to file
    if bin_code != None:
        f = open(raw_bin, "wb")
        if not f:
            print "open file " + raw_bin + " for writing failed."
            sys.exit(-1)
        
        f.write(bin_code)
        f.close()
        
    # Now we have to recalcuate the loaded addresses for Position-independent executables
    if bin_type == "shared_object":
        text_min -= base_addr
        text_max -= base_addr
        entry -= base_addr
        base_addr = 0x0
     
        base_addr = 0x555555554000
        text_min += base_addr
        text_max += base_addr
        entry += base_addr
    
    bin_loaded_info = {
        'base': base_addr,
        'entry': entry,
        'text_min': text_min,
        'text_max': text_max,
        'raw_bin': raw_bin
        }
    return bin_loaded_info 

if __name__ == '__main__':
    #parser = argparse.ArgumentParser(description = 'Process arguements and bin name.')
    #parser.add_argument('app_bin', type = str, help = 'the target application')
    #parser.add_argument('--app-args', type = str, help = 'application arguments')
    #args = parser.parse_args()
    if len(sys.argv) <= 1:
        print "usage: python %s <cmd_line>" % sys.argv[0]
        sys.exit(0)
    cmdline = ""
    for i in range(1, len(sys.argv)):
        cmdline += (sys.argv[i] + " ")
    print "run cmd with pt: ", cmdline
    bin_dir = os.path.dirname(__file__)
    afl_bin = os.path.join(bin_dir, "run_pt")
    app_bin = sys.argv[1]
    
    
    info = binary_loaded_info(app_bin)

    target_addr = 0
    t_file = open('../test/targets.txt', 'r')
    if not t_file:
        #target_addr = 0  # coverage-guided mode
        print "open target file error!"
    else:
        #for line in t_file:
        target_list = t_file.readlines()
        for i in range(0, len(target_list)):
            target_list[i] = target_list[i].strip('\n')
            print "target[",i,"]: ", target_list[i]

        target_addr = int(target_list[0], 16)

    
    print "calculated real program base: ", hex(info['base'])
    print "calculated real program entry: ", hex(info['entry'])
    print "calculated real text_min: ", hex(info['text_min'])
    print "calculated real text_max: ", hex(info['text_max'])
    print "load target_addr: ", hex(target_addr)
    
    cmdline = "sudo %s %s 0x%x 0x%x 0x%x 0x%x %s" % (afl_bin, info['raw_bin'], info['text_min'], info['text_max'], info['entry'], target_addr, cmdline)
    print "cmdline:", cmdline
    os.system(cmdline)



#faddr = open("./min_max.txt", "w")
#faddr.write(str(min_addr) + "\n" + str(max_addr) + "\n" + str(entry))
#faddr.close()



#~ raw_bytes = ld.memory.read_bytes(ld.main_object.entry, max_addr-min_addr)
#~ CODE = ''.join( raw_bytes )
#~ md = Cs(CS_ARCH_X86, CS_MODE_64)
#~ for i in md.disasm(CODE, entry):
    #~ print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

#~ print "len(raw_bytes) = ", len(raw_bytes)
#~ print "entry_point = ", hex(ld.main_object.entry)
#~ print "min_addr = ", hex(min_addr)
#~ print "max_addr = ", hex(max_addr)
#~ print "max_addr - min_addr = ", max_addr - min_addr
#~ print "loader min and max addr: ", ld.min_addr, ld.max_addr
