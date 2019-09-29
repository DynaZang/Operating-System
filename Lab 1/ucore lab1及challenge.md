# 练习1

## 一、ucore.img是如何一步一步生成的？
### 1. 生成`ucore.img`需要`kernel`和`bootblock`
```makefile
# create ucore.img
UCOREIMG	:= $(call totarget,ucore.img)

$(UCOREIMG): $(kernel) $(bootblock)
	$(V)dd if=/dev/zero of=$@ count=10000
	$(V)dd if=$(bootblock) of=$@ conv=notrunc
	$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc

$(call create_target,ucore.img)
```
生成**ucore**需要**kernel**和**bootblock**文件  
创建一个10000块将`/dev/zero`拷贝进去  
将`$(bootblock)`拷贝到同一个位置(*不截短输出文件* )  
将`$(kernel)`拷贝到同一位置(*从输出文件开头跳过1个块后再开始拷贝* )
******
### 2. 生成  kernel

```makefile
# create kernel target
kernel = $(call totarget,kernel)

$(kernel): tools/kernel.ld

$(kernel): $(KOBJS)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

$(call create_target,kernel)
```
在`$(call totraget,kernel)`指令中，将`bin/`前缀加到kernel中  
生成`bin/kernel`   

链接所有的目标文件生成`elf-i386`的内核文件   
通过`make V=`命令得到了

```makefile
+ ld bin/kernel
ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel  obj/kern/init/init.o obj/kern/libs/readline.o obj/kern/libs/stdio.o obj/kern/debug/kdebug.o obj/kern/debug/kmonitor.o obj/kern/debug/panic.o obj/kern/driver/clock.o obj/kern/driver/console.o obj/kern/driver/intr.o obj/kern/driver/picirq.o obj/kern/trap/trap.o obj/kern/trap/trapentry.o obj/kern/trap/vectors.o obj/kern/mm/pmm.o  obj/libs/printfmt.o obj/libs/string.o
```
由此可以看到生成**kernel**的过程中,需要用GCC将目标文件从`.c`转换成如下的`.o`文件
```makefile

obj/kern/init/init.o 
obj/kern/libs/readline.o 
obj/kern/libs/stdio.o 
obj/kern/debug/kdebug.o 
obj/kern/debug/kmonitor.o 
obj/kern/debug/panic.o 
obj/kern/driver/clock.o 
obj/kern/driver/console.o 
obj/kern/driver/intr.o 
obj/kern/driver/picirq.o 
obj/kern/trap/trap.o 
obj/kern/trap/trapentry.o 
obj/kern/trap/vectors.o 
obj/kern/mm/pmm.o  
obj/libs/printfmt.o 
obj/libs/string.o
```
-------

### 3.生成**bootblock**

```makefile
# create bootblock
bootfiles = $(call listf_cc,boot)
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))

bootblock = $(call totarget,bootblock)

$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
	@$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
	@$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
	@$(call totarget,sign) $(call outfile,bootblock) $(bootblock)

$(call create_target,bootblock)
```
`bootflies`表示`boot`下所有文件，包括
```
asm.h
bootasm.S
bootmain.c
```
先把`bootfiles`中的`bootasm.S`,`bootmain.c`编译成`bootasm.o`和`bootmain.o`
再由`bootasm.o`，`bootmain.o`和`sign`生成**bootblock**

生成`bootasm.o`和`bootmain.o`的代码
```makefile
bootfiles = $(call listf_cc,boot)
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
```
通过`make V=`可以看到生成`bootasm.o`和`bootmain.o`的过程
```
+ cc boot/bootasm.S
gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootasm.S -o obj/boot/bootasm.o

+ cc boot/bootmain.c
gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
```

生成`sign`的代码
(`sign.c`是一个C语言小程序，是辅助工具，用于生成一个符合规范的硬盘主引导扇区。)
```makefile
# create 'sign' tools
$(call add_files_host,tools/sign.c,sign,sign)
$(call create_target_host,sign,sign)
```
通过`make V=`看到生成`sign`的过程
```
+ cc tools/sign.c
gcc -Itools/ -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
```
生成**bootblock**的过程
```
+ ld bin/bootblock
ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
```
查询相关资料:

> GCC相关参数：
> -I：添加包含目录
> -fno-builtin：只接受以“__builtin_”开头的名称的内建函数
> -Wall：开启全部警告提示
> -ggdb：生成GDB需要的调试信息
> -m32：为32位环境生成代码，int、long和指针都是32位
> -gstab：生成stab格式的调试信息，仅用于gdb
> -nostdinc：不扫描标准系统头文件，只在-I指令指定的目录中扫描
> -fno-stack-protector：生成用于检查栈溢出的额外代码，如果发生错误，则打印错误信息并退出
> -c：编译源文件但不进行链接
> -o：结果的输出文件

> ld相关参数：
> -m elf_i386：使用elf_i386模拟器
> -nostdlib：只查找命令行中明确给出的库目录，不查找链接器脚本中给出的（即使链接器脚本是在命令行中给出的）
> -T tools/kernel.ld：将tools/kernel.ld作为链接器脚本
> -o bin/kernel：输出到bin/kernel文件

> 生成bootblock和sign工具所需全部OBJ文件的相关命令参数：
> -Os：对输出文件大小进行优化，开启全部不增加代码大小的-O2优化
> -g：以操作系统原生格式输出调试信息，gdb可以处理这一信息
> -O2：进行大部分不以空间换时间的优化

> 链接生成bootblock二进制文件的相关命令参数为：
> -N：将文字和数据部分置为可读写，不将数据section置为与页对齐， 不链接共享库
> -e start：将start符号置为程序起始点
> -Ttext 0x7C00：链接时将".bss"、".data"或".text"置于绝对地址0x7C00处

> 生成ucore.img的命令相关参数：
> if：输入
> of：输出
> count=10000：只拷贝输入的10000块
> conv=notrunc：不截短输出文件
> seek=1：从输出文件开头跳过1个块后再开始复制

## 二、一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？
可以通过研究`sign.c`获取主引导扇区的规范
```c
char buf[512];
    memset(buf, 0, sizeof(buf));
    FILE *ifp = fopen(argv[1], "rb");
    int size = fread(buf, 1, st.st_size, ifp);
    if (size != st.st_size) {
        fprintf(stderr, "read '%s' error, size is %d.\n", argv[1], size);
        return -1;
    }
    fclose(ifp);
    buf[510] = 0x55;
    buf[511] = 0xAA;
    FILE *ofp = fopen(argv[2], "wb+");
    size = fwrite(buf, 1, 512, ofp);
    if (size != 512) {
        fprintf(stderr, "write '%s' error, size is %d.\n", argv[2], size);
        return -1;
    }
```
由上可知，
符合规范的硬盘主引导扇区的特征是
+ 扇区大小为512字节
+ 最后两个字节为`0xAA`
****
# 练习2
### 1. 从CPU加电后执行的第一条指令开始,单步跟踪BIOS的执行。

在`tools/gdbinit`中添加`set architecture i386`一行,
然后进入`lab1/`根目录下,输入`make debug`,得到如下界面:
![1](https://img-blog.csdnimg.cn/20190621134434261.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)
在`kernel/init/init.c:kern_init`函数处有一个自动生成的断点,程序停止在了这里。继续单步执行1条,并执行如下指令强制反汇编

```
define hook-stop
x/i $pc
end
```
打印出的内容如下：
![2](https://img-blog.csdnimg.cn/20190621134458965.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)

****
### 2.在初始化位置0x7c00设置实地址断点,测试断点正常。

![3](https://img-blog.csdnimg.cn/20190621134513679.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)
断点正常并成功进入0x7c00

****
### 3.从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与`bootasm.S`和 `bootblock.asm`进行比较。

为了方便进行比较，查询相关资料后，改写makefile文件:
```makefile
debug: $(UCOREIMG)
        $(V)$(TERMINAL) -e "$(QEMU) -S -s -d in_asm -D  $(BINDIR)/q.log -parallel stdio -hda $< -serial null"
        $(V)sleep 2
        $(V)$(TERMINAL) -e "gdb -q -tui -x tools/gdbinit"
```
重新执行`make debug`命令，在bin目录下生成`q.log`文件
进行比较并截取部分截图如下:
![4](https://img-blog.csdnimg.cn/20190621134541916.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)
由此得到`q.log`文件中在断点后的部分与`bootasm.S`和`bootblock.asm`相同

***
### 4.自己找一个bootloader或内核中的代码位置，设置断点并进行测试。

设置断点0x00007c3e![5](https://img-blog.csdnimg.cn/2019062113455619.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)
从`q.log`中获取到0x00007c3e的指令如下:
`0x00007c3e:  mov    %eax,%ss`
断点设置正常

****
# 练习3
```R
# start address should be 0:7c00, in real mode, the beginning address of the running bootloader
.globl start
start:
.code16                                             # Assemble for 16-bit mode
    cli                                             # Disable interrupts
    cld                                             # String operations increment

    # Set up the important data segment registers (DS, ES, SS).
    xorw %ax, %ax                                   # Segment number zero
    movw %ax, %ds                                   # -> Data Segment
    movw %ax, %es                                   # -> Extra Segment
    movw %ax, %ss                                   # -> Stack Segment
```
关闭中断，将DS,ES,SS寄存器清零
### 1. 为何开启A20，以及如何开启A20?
未开启A20时,此时A20为0,软件可访问的物理内存空间不能超过1MB，且无法发挥Intel 80386以上级别的32位CPU的4GB内存管理能力。
而开启A20,将A20置为1，才可以访问4G内存

**开启方式** :
1. 等待8042 Input buffer为空；
2. 发送`Write 8042 Output Port （P2）`命令到8042 Input buffer；
3. 等待8042 Input buffer为空；
4. 将8042 Output Port（P2）得到字节的第2位置1，然后写入8042 Input buffer；

**代码**:
```
   # Enable A20:
    #  For backwards compatibility with the earliest PCs, physical
    #  address line 20 is tied low, so that addresses higher than
    #  1MB wrap around to zero by default. This code undoes this.
seta20.1:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al                                 # 0xd1 -> port 0x64
    outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port

seta20.2:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al                                 # 0xdf -> port 0x60
    outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1
```
### 2. 如何初始化GDT表？
`lgdt gdtdesc        #加载GDT表`
### 3. 
```
    # GDT从实模式切换到保护模式，
    # 使用GDT（全局描述表，Global Descriptor Table）和段变换，
    # 使得虚拟地址和物理地址相同，
    # 这样，切换过程中不会改变有效内存映射
    # 将CR0的保护允许位PE(Protedted Enable)置1，开启保护模式
    lgdt gdtdesc        #加载GDT表
    movl %cr0, %eax     #加载cr0到eax
    orl $CR0_PE_ON, %eax#将eax的第0位置为1
    movl %eax, %cr0     #将cr0的第0位置为1
```
```
    # 跳转到处于32位代码块中的下一条指令
    # Switches processor into 32-bit mode.
    ljmp $PROT_MODE_CSEG, $protcseg
```
重置其他段寄存器
```
.code32                                             # 32-bit模式汇编代码
protcseg:
    # 设置保护模式的数据段寄存器
    movw $PROT_MODE_DSEG, %ax                       # Our data segment selector
    movw %ax, %ds                                   # -> DS: Data Segment
    movw %ax, %es                                   # -> ES: Extra Segment
    movw %ax, %fs                                   # -> FS
    movw %ax, %gs                                   # -> GS
    movw %ax, %ss                                   # -> SS: Stack Segment
```
设置栈指针并调用C代码,进入保护模式完成,转到bootmain
```
# Set up the stack pointer and call into C. 
# The stack region is from 0--start(0x7c00)
# 栈区是0~start（0x7c00）
    movl $0x0, %ebp
    movl $start, %esp
    call bootmain
```
****
# 练习4
### 1. bootloader如何读取硬盘扇区的？
读一个硬盘扇区流程:
1. 等待磁盘准备好
2. 发出读取扇区的命令
3. 等待磁盘准备好
4. 把磁盘扇区数据读到指定内存

接下来了解具体怎么从磁盘读取数据

磁盘IO地址和对应功能
第6位: 为1=LBA模式; 0 = CHS模式: 第7位和第5位必须为1
| IO地址 | 功能                                                         |
| ------ | ------------------------------------------------------------ |
| 0x1f0  | 读数据，当0x1f7不为忙状态时，可以读。                        |
| 0x1f2  | 要读写的扇区数，每次读写前，你需要表明你要读写几个扇区。最小是1个扇区 |
| 0x1f3  | 如果是LBA模式，就是LBA参数的0-7位                            |
| 0x1f4  | 如果是LBA模式，就是LBA参数的8-15位                           |
| 0x1f5  | 如果是LBA模式，就是LBA参数的16-23位                          |
| 0x1f6  | 第0~3位：如果是LBA模式就是24-27位 第4位：为0主盘；为1从盘    |
| 0x1f7  | 状态和命令寄存器。操作时先给命令,再读取,如果不是忙状态就从0x1f0端口读数据读数据 |


阅读`bootmain.c`最开始的注释:
```
这是一个简单的bootloader，它唯一的任务就是从第一个硬盘中启动ELF格式的操作系统内核映像。
磁盘格式：
这个程序（bootasm.S和bootmain.c）是bootloader，
它应该被存储在磁盘的第一个扇区内；第二个扇区之后存储的是映像，必须是ELF格式的。
BOOT步骤：
当CPU启动的时候，它把BIOS读入内存中并执行它。BIOS对设备进行初始化，设置中断程序，
并将启动设备（比如硬盘）的第一个扇区读入内存，跳转到这一部分。
假设bootloader就存储在硬盘的第一个扇区中，那么它就开始工作了。bootasm.S中的代码先开始执行，
它开启保护态，并设置C代码能够运行的栈，最后调用本文件中的bootmain()函数；
bootmain()函数将kernel读入内存并跳转到它。
```

读取扇区的过程:
```C
/* readsect - read a single sector at @secno into @dst */
static void
#读入第一个扇区
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                    //读入扇区个数为1
    outb(0x1F3, secno & 0xFF);         //LBA参数的第0-7位
    outb(0x1F4, (secno >> 8) & 0xFF);  //LBA参数的第8-15位
    outb(0x1F5, (secno >> 16) & 0xFF); //LBA参数的第16-23位
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);            //命令0x20: 读扇区

    // wait for disk to be ready
    waitdisk();

    // read a sector 获取数据
    insl(0x1F0, dst, SECTSIZE / 4);
}
```
从`outb()`看出是LBA模式的PIO（Program IO）方式访问硬盘，且一次只读取一个扇区
接下来是读取任意长度的内容的代码:
```c
/* *
 * readseg - read @count bytes at @offset from kernel into virtual address @va,
 * might copy more than asked.
 * 从内核的offset处读count个字节到虚拟地址va中。
 * 复制的内容可能比count个字节多。
 * */
static void
readseg(uintptr_t va, uint32_t count, uint32_t offset) {
    uintptr_t end_va = va + count;

    // 向下舍入到扇区边
    va -= offset % SECTSIZE;

    // 从字节转换到扇区；kernel开始于扇区1
    uint32_t secno = (offset / SECTSIZE) + 1;

    // 如果这个函数太慢，则可以同时读多个扇区。
    // 我们在写到内存时会比请求的更多，但这没有关系
    // 我们是以内存递增次序加载的
    for (; va < end_va; va += SECTSIZE, secno ++) {
        readsect((void *)va, secno);
    }
}
```
### 2. bootloader是如何加载ELF格式的OS？
ELF header在文件开始处描述了整个文件的组织。ELF的文件头包含整个执行文件的控制结构，其定义在elf.h中:
```c
/* file header */
struct elfhdr {
    uint32_t e_magic;     // must equal ELF_MAGIC
    uint8_t e_elf[12];
    uint16_t e_type;      // 1=relocatable, 2=executable, 3=shared object, 4=core image
    uint16_t e_machine;   // 3=x86, 4=68K, etc.
    uint32_t e_version;   // file version, always 1
    uint32_t e_entry;     // 程序入口的虚拟地址
    uint32_t e_phoff;     // program header 表的位置偏移
    uint32_t e_shoff;     // file position of section header or 0
    uint32_t e_flags;     // architecture-specific flags, usually 0
    uint16_t e_ehsize;    // size of this elf header
    uint16_t e_phentsize; // size of an entry in program header
    uint16_t e_phnum;     // program header表中的入口数目
    uint16_t e_shentsize; // size of an entry in section header
    uint16_t e_shnum;     // number of entries in section header or 0
    uint16_t e_shstrndx;  // section number that contains section name strings
};
/* program section header */
struct proghdr {
    uint32_t p_type;   // loadable code or data, dynamic linking info,etc.
    uint32_t p_offset; // file offset of segment
    uint32_t p_va;     // virtual address to map segment
    uint32_t p_pa;     // physical address, not used
    uint32_t p_filesz; // size of segment in file
    uint32_t p_memsz;  // size of segment in memory (bigger if contains bss）
    uint32_t p_flags;  // read/write/execute bits
    uint32_t p_align;  // required alignment, invariably hardware page size
};
```
在`bootmain.c`中:
宏定义:
```
#define SECTSIZE        512
#define ELFHDR          ((struct elfhdr *)0x10000)
```
加载的过程为:
```c
/* bootmain - the entry of bootloader */
void
bootmain(void) {
    // 从磁盘读出kernel映像的第一页，得到ELF头
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // 判断是不是一个合法的ELF的文件
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
    // 先将描述表的头地址存在ph
    // ELF头部有描述ELF文件应加载到内存什么位置的描述表
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    // 按照描述表将ELF文件中数据载入内存
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // // 按照描述表将ELF文件中数据载入内存
    // note: does not return
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

bad:   // ELF文件不合法
    outw(0x8A00, 0x8A00);
    outw(0x8A00, 0x8E00);

    /* do nothing */
    while (1);
}
```
总结:
+ 读取磁盘上的1页（8个扇区），得到ELF头
+ 校验e_magic字段,判断是否为合法ELF文件
+ 从ELF头中获得程序头的位置，从中获得每段的信息
+ 分别读取每段的信息
+ 根据偏移量分别把程序段的数据读取到内存中。
*****
# 练习5 
**补充的代码如下**:
```c
void
print_stackframe(void) {
     uint32_t ebp = read_ebp();
     uint32_t eip = read_eip();
     int i, j;
     for(i=0;ebp!=0&&i<STACKFRAME_DEPTH;i++)
     {
        cprintf("ebp:0x%08x eip:0x%08x", ebp, eip);
        uint32_t *argu= (uint32_t *)ebp+2;
        cprintf("args:0x%08x 0x%08x 0x%08x 0x%08x",*(argu),*(argu+1),*(argu+2),*(argu+3));
        cprintf("\n");
        print_debuginfo(eip-1);//打印函数信息
        eip = ((uint32_t *)ebp)[1]; //更新eip指向上一个函数栈段的返回地址
        ebp = ((uint32_t *)ebp)[0]; //更新ebp指向上一个函数栈段的ebp
     }
}
```
然后在lab1执行`make qemu`
得到运行结果:
![6](https://img-blog.csdnimg.cn/20190621134716748.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)
最后一行的解释:
其对应的是第一个使用堆栈的函数，bootmain.c中的bootmain。
（因为此时ebp对应地址的值为0）
ebp与eip的值对应着bootmain函数的栈帧与调用kern_init后的指令地址。由于kern_init()并没有参数传入，因此这里输出的是bootloader的二进制代码。

*****
# 练习6
### 1. 中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190621134759261.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)

一个表项占8字节
从图中可以看到,第16到31位为中断例程的段选择子,第0到15位和第48到63位分别为偏移量的地位和高位。这几个数据一起决定了中断处理代码的入口地址。

***
### 2.
从`lab1\mm\mmu.h`中获得`SETGATE`宏的定义
```c
#define SETGATE(gate, istrap, sel, off, dpl) {            
    (gate).gd_off_15_0 = (uint32_t)(off) & 0xffff;        
    (gate).gd_ss = (sel);                                
    (gate).gd_args = 0;                                    
    (gate).gd_rsv1 = 0;                                    
    (gate).gd_type = (istrap) ? STS_TG32 : STS_IG32;    
    (gate).gd_s = 0;                                    
    (gate).gd_dpl = (dpl);                                
    (gate).gd_p = 1;                                    
    (gate).gd_off_31_16 = (uint32_t)(off) >> 16;        
}
```
定义中各个参数的含义:
```
gate：为相应的idt[]数组内容，处理函数的入口地址 
istrap：系统段设置为1，中断门设置为0 
sel：段选择子 
off：为__vectors[]数组内容 
dpl：设置特权级。这里中断都设置为内核级，即第0级
```
从`memlayout.h`获得 段选择子 对应的相关定义:
`#define GD_KTEXT    ((SEG_KTEXT) << 3)        // kernel text`
```c
/* idt_init - initialize IDT to each of the entry points in kern/trap/vectors.S */
void
idt_init(void) {
     /* LAB1 YOUR CODE : STEP 2 */
     /* (1) Where are the entry addrs of each Interrupt Service Routine (ISR)?
      *     All ISR's entry addrs are stored in __vectors. where is uintptr_t __vectors[] ?
      *     __vectors[] is in kern/trap/vector.S which is produced by tools/vector.c
      *     (try "make" command in lab1, then you will find vector.S in kern/trap DIR)
      *     You can use  "extern uintptr_t __vectors[];" to define this extern variable which will be used later.
      * (2) Now you should setup the entries of ISR in Interrupt Description Table (IDT).
      *     Can you see idt[256] in this file? Yes, it's IDT! you can use SETGATE macro to setup each item of IDT
      * (3) After setup the contents of IDT, you will let CPU know where is the IDT by using 'lidt' instruction.
      *     You don't know the meaning of this instruction? just google it! and check the libs/x86.h to know more.
      *     Notice: the argument of lidt is idt_pd. try to find it!
      */
     extern uintptr_t __vectors[];
     int i;
     //使用SETGATE宏，对IDT中的每一个表项进行设置
     for(i=0;i<256;i++)
     {
        SETGATE(idt[i],0,GD_KTEXT,__vectors[i],DPL_KERNEL);
     }
     //从用户态权限切换到内核态权限
     SETGATE(idt[T_SWITCH_TOK],0,GD_KTEXT,__vectors[T_SWITCH_TOK], DPL_USER);
     lidt(&idt_pd);//使用lidt指令加载IDT
}
```
***
### 3. 
从`clock.c`获得关于clock的初始化代码:
```c
/* *
 * clock_init - initialize 8253 clock to interrupt 100 times per second,
 * and then enable IRQ_TIMER.
 * */
void
clock_init(void) {
    // set 8253 timer-chip
    outb(TIMER_MODE, TIMER_SEL0 | TIMER_RATEGEN | TIMER_16BIT);
    outb(IO_TIMER1, TIMER_DIV(100) % 256);
    outb(IO_TIMER1, TIMER_DIV(100) / 256);

    // initialize time counter 'ticks' to zero
    ticks = 0; //时钟计数

    cprintf("++ setup timer interrupts\n");
    pic_enable(IRQ_TIMER);
}
```
所以可知clock的计数器为ticks。
同时，从`trap.c`的宏定义`#define TICK_NUM 100`可得, TICK_NUM 已经定义为100。
代码补全:
```c
 case IRQ_OFFSET + IRQ_TIMER:
        /* LAB1 YOUR CODE : STEP 3 */
        /* handle the timer interrupt */
        /* (1) After a timer interrupt, you should record this event using a global variable (increase it), such as ticks in kern/driver/clock.c
         * (2) Every TICK_NUM cycle, you can print some info using a funciton, such as print_ticks().
         * (3) Too Simple? Yes, I think so!
         */
        ticks ++;
        if (ticks == TICK_NUM)
        {
            ticks = 0;   //将ticks重置为0
            print_ticks();
        }
        break;
```
进行测试,截图如下:
![7](https://img-blog.csdnimg.cn/20190621134905523.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)
输入a后确实会打印。
*****
# challenge 
目的是完成`init.c`中的`switch_to_user`和`switch_to_kernel`和`trap.c`中`trap_dispatch()`的`case T_SWITCH_TOU`和`case T_SWITCH_TOK`四个函数

首先是`init.c`中的`switch_to_use`
从中断返回时，会多pop两位，并用这两位的值更新ss、sp， 所以要先把栈压两位。
```c
static void
lab1_switch_to_user(void) {
    //LAB1 CHALLENGE 1 : TODO
    asm volatile(
        //设置新栈顶指向switchktou，当返回出栈，则出栈switchktou 中的值。
        "sub $0x8, %%esp \n" 
        "int %0 \n"//调用 T_SWITCH_TOU 中断
        "movl %%ebp, %%esp" //恢复栈指针
   :
   : "i"(T_SWITCH_TOU)
    );
}
```
调用了`T_SWITCH_TOU`中断，在`trap.c`中完善该函数
首先创建两个trapframe
`struct trapframe switchktou, *switchutok;`
```c
case T_SWITCH_TOU:
        if (tf->tf_cs != USER_CS) {
            //当前在内核态，需要建立切换到用户态所需的trapframe结构的数据switchktou
            switchktou = *tf;    //设置switchktou
            //将cs，ds，es，ss设置为用户态。
            switchktou.tf_cs = USER_CS;
            switchktou.tf_ds = switchktou.tf_es = switchktou.tf_ss = USER_DS;
            switchktou.tf_esp = (uint32_t)tf + sizeof(struct trapframe) - 8;
		    //设置EFLAG的I/O特权位，使得在用户态可使用in/out指令
            switchktou.tf_eflags |= FL_IOPL_MASK;
            //设置临时栈，指向switchktou，这样iret返回时，CPU会从switchktou恢复数据，而不是从现有栈恢复数据。
            *((uint32_t *)tf - 1) = (uint32_t)&switchktou;
        }
```
此时先将tf复制到创建的栈switchktou，然后在switchktou中进行修改，再修改指针
![8](https://img-blog.csdnimg.cn/20190621135016502.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)

其次是`init.c`中的`switch_to_kernel`
```c
static void
lab1_switch_to_kernel(void) {
    //LAB1 CHALLENGE 1 :  TODO
    //发出中断时，CPU处于用户态，我们希望处理完此中断后，CPU继续在内核态运行，
    //把tf->tf_cs和tf->tf_ds都设置为内核代码段和内核数据段
	asm volatile (
	    "int %0 \n"//调用T_SWITCH_TOK号中断。
	    "movl %%ebp, %%esp \n"//因为我们强行改为内核态，会让cpu认为没有发生特权级转换。于是，%esp的值就不对了
	    : 
	    : "i"(T_SWITCH_TOK)
	);
}
```
```c
case T_SWITCH_TOK:
    if (tf->tf_cs != KERNEL_CS) {
        //发出中断时，CPU处于用户态，我们希望处理完此中断后，CPU继续在内核态运行，
        //所以把tf->tf_cs和tf->tf_ds都设置为内核代码段和内核数据段
      tf->tf_cs = KERNEL_CS;
      tf->tf_ds = tf->tf_es = KERNEL_DS;
      //设置EFLAGS，让用户态不能执行in/out指令
      tf->tf_eflags &= ~FL_IOPL_MASK;

      switchutok = (struct trapframe *)(tf->tf_esp - (sizeof(struct trapframe) - 8));
      //相当于在栈中挖出sizeof(tf-8)的空间
      memmove(switchutok, tf, sizeof(struct trapframe) - 8);
      *((uint32_t *)tf - 1) = (uint32_t)switchutok;
     }
     break;
```
![9](https://img-blog.csdnimg.cn/20190621135038949.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80Mzk5NTA5Mw==,size_16,color_FFFFFF,t_70)
最后CPU会从switchutok恢复数据会，进入内核态。
通过和同学的交流发现，其实最后三句不写，直接修改tf也能在`make grade`中获得满分，但这样写的话会更规范点。