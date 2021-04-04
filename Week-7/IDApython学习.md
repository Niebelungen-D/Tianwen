从头硬撸一个IDApython脚本，记录一下自己的学习过程。
## MIPS
### 通用寄存器
在MIPS体系结构中有32个通用寄存器（每个寄存器大小根据芯片型号不同而不同，在一般情况下，32位处理器中每个寄存器的大小是32位，即4字节），在汇编程序中可以用编号$0~\$31表示，也可以用寄存器的名字表示，如\$sp、\$t1、\$ra等。堆栈是从内存的高地址方向向低地址方向增长的。

| REGISTER |   NAME   |                                USAGE                                 |
|:--------:|:--------:|:--------------------------------------------------------------------:|
|    $0    |  $zero   |                 常量0，和0值作比较运算是常用该寄存器                 |
|    $1    |   $at    |      汇编保留保留寄存器，不可做其他用途（Assembler Temporary）       |
| \$2-\$3  | $v0-\$v1 |    存储函数的返回值。如果返回值为1字节，则只有\$v0有效（Values）     |
|  $4-\$7  | $a0~\$a3 |   作为函数调用时传递的前4个参数，不够时才使用堆栈传递（Arguments）   |
| $8-\$15  | $t0~\$t7 |          临时寄存器，无需保证函数调用的恢复（Temporaries）           |
| $16-\$23 | $s0~\$s7 |            函数调用后这些寄存器需要被恢复（Saved Values）            |
| $24-\$25 | $t8~\$t9 |                 临时寄存器的拓展补充（Temporaries）                  |
| $26-\$27 | $k0~\$k1 |             系统保留寄存器，请勿使用（Kernel reserved）              |
|   $28    |   $gp    | 全局指针，静态数据访问时需要保证在gp指定的64kb范围（Global Pointer） |
|   $29    |   $sp    |                      堆栈指针（Stack Pointer）                       |
|   $30    | $s8/\$fp |                     Saved value / Frame Pointer                      |
|   $31    |   $ra    |               存放函数调用返回的地址（Return Address）               |
### 特殊寄存器
MIPS32架构中定义了3个特殊寄存器，分别是PC、HI、和LO。

### 基本栈帧结构

完整的栈帧结构具有5个部分：
```c
Low Address        Top of Stack frame
+----------------------------------+
|    Local Data Storage Section    |
+----------------------------------+
|                Pad               |
+----------------------------------+
|    Return Address Section        |
+----------------------------------+
|    Saved Registers Section       |
+----------------------------------+
|        Argument Section          |
+----------------------------------+
High Address    Bottom of Stack frmae
```
-   参数段（Argument Section）。参数段旨在函数调用子函数（非叶子函数）时出现。
    -   编译器在生成这个段的时候保证了它的大小足够所有的参数存放。
    -   参数段最小4\*4 byte 大小。
    -   参数寄存器\$a0~$a3用于传递子函数的前4个参数。这几个参数将不会复制到栈帧空间中去（注意：栈帧空间仍将为其预留等额空间），额外的参数将复制进入参数段（偏移为16，20，24等等）。
    -   参数端在栈帧的低地址端（栈顶位置）。

-   寄存器保存段（Saved Registers Section）。当函数需要使用到$s0~\$s7中的寄存器时出现。
    -   寄存器保存端将为每个需要保存的寄存器准备4 byte大小的的空间。
    -   函数的开场白（Prologue）会在函数入口处将每一个需要保存的寄存器的值保存到寄存器保存段中，然后在返回前将其恢复到对应的寄存器中。
    -   如果函数本身没有对寄存器的内容进行改变，则不需要进行保存/恢复这个过程。
    -   寄存器保存段在参数段后面（栈底方向）。
-   返回地址段（Return Address Section）。当函数调用了其他子函数时出现。
    -   返回地址段只有1字节大小，即用1字节来保存返回地址。
    -   返回地址寄存器\$ra将在函数入口处被复制到返回地址段，再函数返回前恢复到$ra中。
    -   返回地址段在寄存器保存段后面（栈底方向）。
-   填充段（Pad）。当参数段+寄存器保存段+返回地址段的大小不是8的倍数时出现。
    -   填充段只有1字节大小（要么就没有）。
    -   填充段不存数据。
    -   填充段在返回地址段后面（栈底方向）。
-   局部数据存储段（Local Data Storage Section）。当函数使用了局部参数或必须保存寄存器参数时出现。
    -   局部数据存储段的大小是由子程序对于局部数据存储的需求决定的，它总是8的倍数。
    -   局部数据存储段的数据是函数私有的，是被调用函数和函数的子函数都无法访问的数据。

局部数据存储段在填充段后面（栈底方向），是栈帧的最后一部分。
## ARM
参考：
[ARM指令集](https://blog.csdn.net/zqixiao_09/article/details/50726544)
《逆向工程权威指南》
[ARM教程](https://azeria-labs.com/writing-arm-assembly-part-1/)
		
## IDApython Basic
![[idapython-api.png]]
```python
here()
#当前选中行的地址

idc.set_color(ea, CIC_SEGM, 0x00ff00)
#设置颜色

idc.get_name_ea_simple("gets") 
#查找指定函数名,如果return 0xffff..ff则地址不存在(即BADADDR)

idc.get_first_cref_to(addr)
#对相关地址的第一个xref：

idc.get_next_cref_to(To, current)
#下一个的xref

ida_funcs.get_func(addr).start_ea
#获取当前地址所属函数的起始地址

get_arg_addrs(call_addr)
#获取当前函数的参数赋值地址（传参寄存器在背赋值的地址）

get_func_attr(call_addr, FUNCATTR_FRSIZE)
#获取函数的缓冲区大小

print_insn_mnem(ea)
#获取操作符

set_cmt(ea, cmt, 0)
#添加注释
```
**定位函数**
在查找指定函数名时，若直接使用函数名，基本都会找到got表，从got表找xref只会返回一个，也就是plt表。而从plt表再找xref就可以找到text段函数调用的地址。若在函数名前加“.”可以直接查找到plt。
## IDApy first attempt
[IDAPython mipsAudit](https://github.com/giantbranch/mipsAudit)（作者的名字似曾相识，应该不少人用过他的pwn虚拟机）
这是一个MIPS静态汇编审计辅助脚本：
1.  找到危险函数的调用处，并且高亮该行（也可以下断点,这个需要自己去源码看吧）
    
2.  给参数赋值处加上注释
    
3.  最后以表格的形式输出函数名，调用地址，参数，还有当前函数的缓冲区大小

参考作者思路得到：
```python
from idaapi import *
from idc import *
from idautils import *
from prettytable import PrettyTable

dangerous_funcs = [
    "strcpy", "strncpy", "scanf", "gets", "read",
    "system", "execve", "memcpy", "memncpy"
]

attention_function = [
    "printf"
]

one_arg_function = [
    "gets", "system"
]

two_arg_function = [
    "strcpy",
]

three_arg_function = [
    "memcpy", "execve", "read", "strncpy"
]

format_function_offset_dict = [
    "printf"
]

arg_reg = [
	"rdi", "edi", "di", "dil",
	"rsi", "esi", "si", "sil",
	"rdx", "edx", "dx", "dl",
	"rcx", "ecx", "cx", "cl",
	"r8", "r8d", "r8w", "r8b",
	"r9", "r9d", "r9w", "r9b",
    "r10", "r10d", "r10w", "r10b",
    "r11", "r11d", "r11w", "r11b",
    "r12", "r12d", "r12w", "r12b",
    "r13", "r13d", "r13w", "r13b",
    "r14", "r14d", "r14w", "r14b",
    "r15", "r15d", "r15w", "r15b"
]

def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getaddr(func_name):
    addr = get_name_ea_simple(func_name)
    if addr != BADADDR:
        for ref in CodeRefsTo(addr, 0):
            return ref
    return False

#获得func的调用（call）地址，并分析其参数
def audit(func_name):
    addr = getaddr(func_name)
    argv_num = 0
    if addr == False:
        return False
    call_addr = RfirstB(addr)
    print(printFunc(func_name))
    #print(hex(call_addr),GetDisasm(call_addr))
    if func_name in one_arg_function:
        argv_num = 1
    elif func_name in two_arg_function:
        argv_num = 2
    elif func_name in three_arg_function:
        argv_num = 3
    table_head = ["func_name", "addr"]
    for num in range(0,argv_num):
        table_head.append("arg"+str(num+1))
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)
    while call_addr != BADADDR:
        # set color ———— green (red=0x0000ff,blue = 0xff0000)
        SetColor(call_addr, CIC_ITEM, 0x00ff00)
        row = deal_argv(call_addr, func_name, argv_num)
        call_addr = RnextB(addr, call_addr)
        table.add_row(row)
    print(table)

def audit_format(func_name):
    addr = getaddr(func_name)


def deal_argv(call_addr, funcname, argvnum):
    #prev_instr = prev_head(call_addr)
    addr = "0x%x" % call_addr
    ret_list = [funcname, addr]
    addrlist = list(get_arg_addrs(call_addr))
    comment = "addr:" + str(hex(call_addr))
    local_buf_size = GetFunctionAttr(call_addr, FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    for arg in addrlist:
        if arg != BADADDR:
            set_color(arg, CIC_ITEM, 0x00FFFF) #yellow
            src = find_src(arg)
            MakeComm(arg, comment)
            ret_list.append(src)
        else:
            ret_list.append("get fail")
    ret_list.append(local_buf_size)
    return ret_list

def find_src(addr):
    jmp_list = ["jmp", "jz", "jnz", "je", "jle", "jl", "jg", "js", "jns", "ja"]
    nochange = ["push", "pop", "test"]
    current = addr
    func = get_func(addr).start_ea
    src = GetOpnd(current, 1)
    while current >= func:
        current = prev_head(current)
        reg = GetOpnd(current, 0)
        mnem = GetMnem(current)
        if mnem in jmp_list:
            return src
        if reg==src and mnem not in nochange:
            src = GetOpnd(current, 1)
        if src in arg_reg:
            return src

    return src

def main():
    for func_name in dangerous_funcs:
        audit(func_name)
    for func_name in format_function_offset_dict:
        audit_format(func_name)

if __name__ == '__main__':
    main()

print("Over!")

```
基本实现了x86-64下的辅助审计，但对格式化字符串漏洞的处理还没有完善。目前对其处理思路是判断其`fmt`是否是可控的，如果用户可控，则可以断定为格式化字符串漏洞。
对于MIPS来说，其指令相较于x86-64很精简了（毕竟是RISC），参数回溯在x86-64下有着更加复杂的情况。
## try again
Sakura师傅提供了一个功能更加完善的插件：[firmeye](https://github.com/firmianay/firmeye)
** firmeye - IoT固件漏洞挖掘工具**
firmeye 是一个 IDA 插件，基于敏感函数参数回溯来辅助漏洞挖掘。我们知道，在固件漏洞挖掘中，从敏感/危险函数出发，寻找其参数来源，是一种很有效的漏洞挖掘方法，但程序中调用敏感函数的地方非常多，人工分析耗时费力，通过该插件，可以帮助排除大部分的安全调用，从而提高效率。
-   漏洞类型支持：缓冲区溢出、命令执行、格式化字符串
-   架构支持：ARM

接下来的目标是参考其参数回溯的逻辑，实现x86-64下的挖掘工具。
先说一下firmeye的思路，基于dfs的参数回溯。首先是，在块内搜索，会将所有对回溯目标寄存器有影响的指令输出，无论是直接还是间接。
```python 
   	def trace_handle(self, addr, reg):
        """
        处理回溯事件
        """
        next_addr = ida_bytes.prev_head(addr, 0)
        next_reg = self.get_next_reg(addr, reg)

        return (next_addr, next_reg)
```
其回溯操作，每次地址上移，`get_next_reg`函数都会判断前一个指令是否对目标寄存器有影响。若是遇到`mov dest_reg, src_reg`就会返回`src_reg`。从而对新的寄存器进行回溯。
我觉得这个思路还是不错的，参数影响的判断集中在了`get_next_reg`中。sakura师傅希望能对\[rsp+rax+offset]，这样的指令进行进一步的回溯。所以要对firmeye的回溯进行改进。
因为是参数回溯，所以我的思路是只使用他的参数回溯。但是发现若是对所有的危险函数的参数都进行回溯的话，程序会崩溃，而且输出会很不好看。所以打算只回溯单一寄存器，就是让使用者提供回溯开始的地址和目标寄存器。
根据sakura师傅的想法将mov lea等对目标寄存器的各种影响视为传播，所以根据是否会传播将指令分为几类，进行分别处理。

最终实现的代码：[IDApython-plugin](https://github.com/Niebelungen-D/Tianwen/blob/main/week5-6/IDApython-plugin.py)
至于效果嘛，虽然思路是正确的，但是实现的效果似乎不是我想象中的那样。
## FIDL
FIDL是封装Hex-Rays API的python库，提供了反汇编层的API。
[Official Docs](https://fidl.readthedocs.io/en/latest/index.html)
**安装**
```shell
pip install FIDL
```
**导入**
```python
import FIDL
```
or
```python
import FIDL.decompiler_utils as du
```
### 入门
在FIDL中，主要的对象是`controlFlowinator`，这是一个CFG与反编译输出的混合。
**查看函数参数**
```python
import FIDL.decompiler_utils as du

c = du.controlFlowinator(ea = here(), fast= False)
print(c.args)

```
对于这样的一个函数
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  FILE *v3; // rdi

  setbuf(stdin, 0LL);
  v3 = stdout;
  setbuf(stdout, 0LL);
  sub_40068E(v3);
  return 0LL;
}
```
Output:
```c
Name: a1
  Type name: int
  Size: 4
Name: a2
  Type name: char **
  Size: 8
  Pointed object: char *
Name: a3
  Type name: char **
  Size: 8
  Pointed object: char *
{0: , 1: , 2: }
```
`c.args`返回了一个数组，每个元素都是函数的参数，包括以下属性
```python
['__doc__', '__init__', '__module__', '__repr__', '_get_var_type', 'array_type', 'complex_type', 'is_a_function_of', 'is_arg', 'is_array', 'is_constrained', 'is_initialized', 'is_pointer', 'is_signed', 'is_tainted', 'name', 'pointed_type', 'size', 'ti', 'type_name', 'var']
```
- name：名字
- type_name：参数类型
- is\_signed：判断参数是否有符号
- is\_pointer：判断参数是否是指针
- ……

`lvars`用于查看本地参数，以上面那个函数为例
```c
Name: v3
  Type name: FILE *
  Size: 8
  Complex type: FILE
  Pointed object: FILE
{3: }
```
**查看函数调用**
`c.calls`，输出：
```c
Ea: 4006D6
Target's Name: .setbuf
Target's Ea: 400510
Target's ret: void
Args:
 - 0: Rep(type='global', val=6295640)
 - 1: Rep(type='number', val=0)
--------------------------------------
Ea: 4006EA
Target's Name: .setbuf
Target's Ea: 400510
Target's ret: void
Args:
 - 0: Rep(type='global', val=6295632)
 - 1: Rep(type='number', val=0)
	 
	 
--------------------------------------
Ea: 4006F4
Target's Name: sub_40068E
Target's Ea: 40068E
Target's ret: __int64
Args:
Name: v3
  Type name: FILE *
  Size: 8
  Complex type: FILE
  Pointed object: FILE
 - 0: Rep(type='var', val=)
[, , ]
```
例子：
```c
INT_PTR __fastcall DialogFunc(HWND a1, int a2, unsigned __int16 a3)
{
  HWND v3; // rdi
  int v4; // edx
  int v5; // edx
  CHAR *v7; // rbx

  v3 = a1;
  v4 = a2 - 16;
  if ( !v4 )
    goto LABEL_11;
  v5 = v4 - 256;
  if ( !v5 )
  {
    v7 = sub_14000F698("%s Licence", "PuTTY");
    SetWindowTextA(v3, v7);
    sub_14000FCFC(v7);
    SetDlgItemTextA(
      v3,
      1002,
      "PuTTY is copyright 1997-2017 Simon Tatham.\r\n"
      "\r\n"
      "Portions copyright Robert de Bath, Joris van Rantwijk, Delian Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong"
      ", Nicolas Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus Kuhn, Colin Watson, Christopher"
      " Staite, and CORE SDI S.A.\r\n"
      "\r\n"
      "Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated docum"
      "entation files (the \"Software\"), to deal in the Software without restriction, including without limitation the r"
      "ights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to per"
      "mit persons to whom the Software is furnished to do so, subject to the following conditions:\r\n"
      "\r\n"
      "The above copyright notice and this permission notice shall be included in all copies or substantial portions of t"
      "he Software.\r\n"
      "\r\n"
      "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO"
      " THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE C"
      "OPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OT"
      "HERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.");
    return 1i64;
  }
  if ( v5 == 1 && a3 - 1 <= 1 )
LABEL_11:
    EndDialog(a1, 1i64);
  return 0i64;
}
```
通过脚本获得PuTTY’s license的内容
```python
import FIDL.decompiler_utils as du

c = du.controlFlowinator(ea = here(), fast= False)

for k in c.calls:
	if k.name == 'SetDlgItemTextA':
		break

lic = k.args[2]
print(lic.type)
s = lic.val
print(s)
```
**变量的重命名**
看文档的例子，
```c
__int64 cgp_sneaky_direct_asg()
{
  HMODULE v0; // rax
  HMODULE v1; // rbx

  v0 = sub_140065B68("comctl32.dll");
  v1 = v0;
  if ( v0 )
    qword_1400C0DD0 = GetProcAddress(v0, "InitCommonControls");
  else
    qword_1400C0DD0 = 0i64;
  if ( v1 )
    qword_1400C0DD8 = GetProcAddress(v1, "MakeDragList");
  else
    qword_1400C0DD8 = 0i64;
  if ( v1 )
    qword_1400C0DE0 = GetProcAddress(v1, "LBItemFromPt");
  else
    qword_1400C0DE0 = 0i64;
  if ( v1 )
    qword_1400C0DE8 = GetProcAddress(v1, "DrawInsert");
  else
    qword_1400C0DE8 = 0i64;
  return qword_1400C0DD0();
}
```
脚本：
```python
import FIDL.decompiler_utils as du


callz = du.find_all_calls_to_within(f_name='GetProcAddress', ea=here())
for co in callz:
    # The *second* argument of ``GetProcAddress`` is the API name
    api_name = co.args[1].val

    # double check :)
    if not du.is_asg(co.node):
        continue

    lhs = co.node.x
    if du.is_global_var(lhs):
        g_addr = du.value_of_global(lhs)
        new_name = "g_ptr_{}".format(api_name)
        MakeName(g_addr, new_name)
```
### 简单栈溢出检查
```python
import FIDL.decompiler_utils as du
from idaapi import *
from idc import *
from idautils import *

def stack_overflow(f_ea):
    result = []
    readz = du.find_all_calls_to_within('read', ea=f_ea)
    getsz = du.find_all_calls_to_within('gets', ea=f_ea)
    systemz = du.find_all_calls_to_within('system', ea=f_ea)

    for call in readz :
        var_dest = call.args[1].val
        var_size = call.args[2].val
        if call.args[1].type == "global":
            result.append("check at {:#x} : {}, maybe overflow".format(call.ea, du.my_get_func_name(call.ea)))
        else :
            dest_size = var_dest.array_len
            if var_size > dest_size :
                result.append("check at {:#x} : {}, maybe overflow".format(call.ea, du.my_get_func_name(call.ea)))
                # print("check at {:#x} in {}, maybe overflow".format(call.ea, du.my_get_func_name(call.ea)))
    for call in getsz:
        result.append("check at {:#x} : {}, maybe overflow".format(call.ea, du.my_get_func_name(call.ea)))
        
    for call in systemz:
        cmd = call.args[0].val
        if 'sh' in cmd:
            result.append("check at {:#x} : {}, command exceved".format(call.ea, du.my_get_func_name(call.ea)))
    return result

def main():
    results = []
    funcs = du.NonLibFunctions(BeginEA(), min_size=0)
    for f in funcs:
        if idc.SegName(f) == '.text':
            temp = stack_overflow(f)
            if temp:
                results = results + temp
    for r in results:
        print(r)

if __name__ == '__main__':
    main()

```
其核心API能实现的功能似乎不多，发现其还使用了Lighthouse的API。仅使用FIDL的话，对参数的处理还是有限，如果能处理好，FIDL和汇编层IDApython的数据结构问题，应该更好分析。