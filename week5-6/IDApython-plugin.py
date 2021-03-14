from enum import IntEnum
import re
from functools import reduce, wraps

import idc
import idaapi
import idautils

dangerous_funcs = [
    "strcpy", "execve", "read", "system", "memcpy"
]
DEBUG = True
SINK_FUNC = []
INST_LIST = []
# 当回溯过程中遇到其他函数对寄存器有影响，则按规则切换回溯对象。
SOURCE_FUNC = {
    'gets': {       # char *gets(char *s);
        'dest': '0',
        'src': 'None',
    },

    'scanf': {      # int scanf(const char *format, ...);
        'dest': '6',
        'src': 'None',
    },

    'strcat': {     # char *strcat(char *dest, const char *src)
        'dest': '7',
        'src': '6',
    },

    'strcpy': {     # char *strcpy(char *dest, const char *src);
        'dest': '7',
        'src': '6',
    },

    'memcpy': {     # void *memcpy(void *dest, const void *src, size_t n);
        'dest': '7',
        'src': '6',
    }
}

class RegNo(IntEnum):
    R_ax = 0,
    R_cx = 1,
    R_dx = 2,
    R_bx = 3,
    R_sp = 4,
    R_bp = 5,
    R_si = 6,
    R_di = 7,
    R_r8 = 8,
    R_r9 = 9,
    R_r10 = 10,
    R_r11 = 11,
    R_r12 = 12,
    R_r13 = 13,
    R_r14 = 14,
    R_r15 = 15

# logger
class FELogger():
    """
    日志、调试配置管理类
    """

    enable_dbg = DEBUG
    log_path = ''
    log_fd = None
    time_cost = {}

    @classmethod
    def get_dbg_mode(cls):
        return cls.enable_dbg

    @classmethod
    def enable_debug(cls):
        cls.enable_dbg = True

    @classmethod
    def disable_debug(cls):
        cls.enable_dbg = False

    @classmethod
    def reload(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if cls.get_dbg_mode():
                cur_workpath = os.getcwd()
                log_filename = '%s.xdbg' % idaapi.get_root_filename()
                log_filepath = os.path.join(cur_workpath, log_filename)
                cls.log_path = log_filepath
                if cls.log_fd:
                    cls.log_fd.close()
                    cls.log_fd = None
                cls.log_fd = open(cls.log_path, 'a')
            return func(*args, **kwargs)
        return wrapper

    @classmethod
    def log_time(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            s_time = time.perf_counter()
            ret_t = func(*args, **kwargs)
            e_time = time.perf_counter()
            if not func.__name__ in cls.time_cost:
                cls.time_cost[func.__name__] = 0
            cls.time_cost[func.__name__] += e_time - s_time
            return ret_t
        return wrapper

    @classmethod
    def show_time_cost(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ret_t = func(*args, **kwargs)
            for func_name in cls.time_cost:
                cls.info('%s: %f seconds' %
                         (func_name, cls.time_cost[func_name]))
            return ret_t
        return wrapper

    @classmethod
    def log(cls, level, msg, debug):
        if level == 'console':
            msg_t = '%s\n' % msg
        else:
            msg_t = '[%s] %s\n' % (level, msg)

        if cls.log_fd:
            if cls.enable_dbg or debug:
                cls.log_fd.write(msg_t)
                cls.log_fd.flush()

        ida_kernwin.msg(msg_t)
        if level == 'warn' or level == 'erro':
            ida_kernwin.warning(msg_t)

    @classmethod
    def console(cls, msg, debug=False):
        cls.log(level='console', msg=msg, debug=debug)

    @classmethod
    def info(cls, msg, debug=False):
        cls.log(level='info', msg=msg, debug=debug)

    @classmethod
    def warn(cls, msg, debug=False):
        cls.log(level='warn', msg=msg, debug=debug)

    @classmethod
    def erro(cls, msg, debug=False):
        cls.log(level='erro', msg=msg, debug=debug)


# reg_or_mm的格式
# {'reg' : str, 'mm' : (int, int, int, int)}
# 如果是reg，则reg为str类型的字符串0-15，否则就是int类型的-1
# 如果是mm，则mm为int类型的四元组(a,b,c,d);

# 经验测试:
# 1. [reg]
# 2. [reg1 + reg2]
# 3. [reg + imm]
# 4. [reg1 + reg2 + imm]

# [r15]
# Python>inst = idautils.DecodeInstruction(0xE939)
# Python>inst.Op1.specflag1
# 0x0
# Python>inst.Op1.phrase
# 0xf
# Python>inst.Op1.type
# 0x3
# Python>get_mm(inst,inst.Op1)
# (0xf, -0x1, 0x0, 0x0)
# ----------------------------------------------------------------------
# [rdi+rax*2]
# Python>inst = idautils.DecodeInstruction(0xF00F)
# Python>inst.Op2.type
# 0x3
# Python>get_mm(inst, inst.Op2)
# (0x7, 0x0, 0x1, 0x0)
# Python>inst.Op2.phrase (错误，结果不是base)
# 0x4
# Python>inst.Op2.specflag1
# 0x1
# ----------------------------------------------------------------------
# [r13-6]
# Python>inst = idautils.DecodeInstruction(0xEB23)
# Python>inst.Op1.specflag1
# 0x0
# Python>inst.Op1.phrase
# 0xd
# Python>inst.Op1.addr
# 0xfffffffffffffffa
# Python>inst.Op1.type
# 0x4
# (0xd, -0x1, 0x0, 0xfffffffffffffffa)
 
# [r15+2]
# Python>inst = idautils.DecodeInstruction(0xF024)
# Python>get_mm(inst, inst.Op2)
# (0xf, -0x1, 0x0, 0x2)
# Python>inst.Op2.type
# 0x4
# Python>inst.Op2.specflag1
# 0x0

# [rsp+68h+var_58]
# Python>inst = idautils.DecodeInstruction(0xEB2B)
# Python>inst.Op1.specflag1
# 0x1
# Python>print(x86_base_reg(inst,inst.Op1))
# 4
# Python>get_mm(inst, inst.Op1)
# (0x4, -0x1, 0x0, 0x10)
# ----------------------------------------------------------------------
# [r14+r15-8]
# Python>inst.Op2.type
# 0x4
# Python>get_mm(inst, inst.Op2)
# (0xe, 0xf, 0x0, 0xfffffffffffffff8)
# Python>inst.Op2.phrase
# 0xc
# Python>inst.Op2.specflag1
# 0x1

# helper
REX_B = 1
REX_X = 2
REX_R = 4
REX_W = 8
INDEX_NONE = 4
R_none = -1

def sib_base(insn, x):
    base = x.specflag2 & 7
    if insn.insnpref & REX_B:  # x86_64
        base |= 8
    return base

def x86_base_reg(insn, x):
    if x.specflag1:
        if x.type == idaapi.o_mem:
            return R_none
        return sib_base(insn, x)
    else:
        return x.phrase

def x86_index_reg(insn, x):
    if x.specflag1:
        idx = sib_index(insn, x)
        if idx != INDEX_NONE:
            return idx
        return R_none
    else:
        return R_none

def sib_index(insn, x):
    index = (x.specflag2 >> 3) & 7
    if (insn.insnpref & REX_X) != 0:
        index |= 8
    return index

def x86_scale(x):
    return sib_scale(x) if x.specflag1 else 0


def sib_scale(x):
    scale = (x.specflag2 >> 6) & 3
    return scale

def get_mm(insn, x):
    return (x86_base_reg(insn, x), x86_index_reg(insn, x), x86_scale(x), x.addr)

def hexstr(num):
    """
    IDA内可双击跳转的地址形式
    """
    return format(num, '#010x')

def get_mnem(ea):
    """
    获取操作符
    """
    mnem = idc.print_insn_mnem(ea)
    return mnem

def name_to_addr(s):
    """
    返回任意名称的地址：function, label, global...
    """
    if s[0] == '_':
        print(s)
        tmp = list(s)
        tmp[0] = '.'
        s = ''.join(tmp)
    addr = idaapi.get_name_ea(idc.BADADDR, s)
    if addr == idc.BADADDR:
        print("[Error] name_to_addr: Failed to find '%s' symbol" % s)
        return None
    return addr


def get_buffersize(call_addr):
    local_buf_size = GetFunctionAttr(call_addr, FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    return local_buf_size

class FESinkFuncMgr():
    """sink函数管理器
    提供获取sink函数的调用地址和交叉引用信息的工具函数
    sink_func_info: 默认存储sink函数全局配置信息
    """

    def __init__(self, sink_func_info=SINK_FUNC):
        self.sink_func_info = sink_func_info

    def gen_sink_func_addr(self):
        for func_addr in idautils.Functions():
            func_name = idaapi.get_func_name(func_addr)
            if func_name in self.sink_func_info:
                yield (func_name, func_addr)
            else:
                continue

    def gen_func_xref(self, func_addr):
        for xref_addr in idautils.CodeRefsTo(func_addr, 0):
            if idc.get_func_flags(xref_addr) != -1:
                yield xref_addr
            else:
                continue

    def get_func_xref(self, func_addr):
        return [xref_addr for xref_addr in self.gen_func_xref(func_addr)]

    def gen_sink_func_xref(self):
        for func_name, func_addr in self.gen_sink_func_addr():
            yield (func_name, self.get_func_xref(func_addr))

    def get_one_func_xref(self, func_name):
        for func_addr in idautils.Functions():
            func_name_t = idaapi.get_func_name(func_addr)
            if func_name == func_name_t:
                return self.get_func_xref(func_addr)
            else:
                continue

class FEArgsTracer():
    """参数回溯器
    从call_addr开始向上回溯
    寻找影响当前寄存器值的指令地址
    基于DFS的块际回溯
    """

    def __init__(self, addr, reg_or_mm, max_node=256):
        self.trace_addr = addr  #开始回溯的地址
        self.trace_reg = reg_or_mm   #开始回溯的寄存器

        self.init_tree()
        self.init_cache()
        self.init_blk_cfg()

        self.max_node = max_node

    def init_blk_cfg(self):
        """
        初始化基本块CFG图
        """
        func_t = idaapi.get_func(self.trace_addr)
        if func_t:
            self.cfg = idaapi.FlowChart(func_t)
        else:
            self.cfg = []

    def get_blk(self, addr):
        """
        获取addr所在的基本块
        """
        for blk in self.cfg:
            if blk.start_ea <= addr and addr < blk.end_ea:
                return blk
        return None

    def create_tree_node(self, addr, prev=None):
        """
        创建树节点
        """
        return {
            'addr': addr,
            'prev': prev,
        }

    def init_tree(self):
        """
        初始化回溯树
        """
        self.tree = self.create_tree_node(self.trace_addr)

    def push_cache_node(self, addr, key):
        """
        将节点地址添加到缓存列表
        """
        # print("sakura")
        print(self.cache)
        self.cache['all_node'].add(addr)
        return True
        # if key in self.cache:
        #     self.cache['all_node'].add(addr)
        #     if addr not in self.cache[key]:
        #         self.cache[key].add(addr)
        #         print(self.cache)
        #         return True
        # return False

    def init_cache(self):
        """
        初始化缓存列表，记录回溯过程中经过的节点地址
        """
        self.cache = {'addr': set(), 'all_node': set()}
        # for r in [str(i) for i in range(16)]:
        #     self.cache.update({r: set()})

    def get_next_reg_or_mm(self, addr, reg_or_mm):
        """
        寻找下一个赋值来源寄存器或者内存值
        返回寄存器名或内存值或None
        """
        addr_t = addr
        #print(addr_t)
        mnem = get_mnem(addr_t)
        #print(mnem)
        line = idc.generate_disasm_line(addr_t, 0)
        #print(line)
        inst = idautils.DecodeInstruction(addr_t)
        reg_or_mm_t = reg_or_mm
        if reg_or_mm['reg'] != -1: # 回溯对象是reg：1，or mm：0
            reg_or_mm_flag = 1
        else:
            reg_or_mm_flag = 0
        if mnem.startswith('call') and addr_t != self.trace_addr:
            # case : call func_xxx
            FELogger.info("途径函数\t"+hexstr(addr)+"\t"+line)
            func_name = idc.get_func_name(addr_t)
            func_addr = name_to_addr(func_name) #定位函数调用地址
            if func_addr is not None:
                #print(func_addr)
                #print(RegNo.R_ax)
                if reg_or_mm_flag and reg_or_mm_t['reg'] == str(RegNo.R_ax):
                    #回溯的寄存器为rax，找rax的赋值点
                    does_return = idaapi.get_func(func_addr).does_return()
                    #print(does_return)
                    if does_return == True: #call func_xxx 的返回值为rax赋值
                        FELogger.info("找到赋值点\t" + hexstr(addr) + "\t" + line)
                        return None
                else: #!reg or !rax
                    if func_name in SOURCE_FUNC and reg_or_mm_flag and reg_or_mm_t == SOURCE_FUNC[func_name]['dest']:
                        # func_xxx 对寄存器有影响
                        reg_or_mm_t['reg'] = SOURCE_FUNC[func_name]['src']
                        if reg_or_mm_t['reg'] == 'None':
                            FELogger.info("找到赋值点\t" + hexstr(addr) + "\t" + line)
                            return None
                        else:
                            FELogger.info("传播到" + reg_or_mm_t['reg'] + "\t" + hexstr(addr) + "\t" + line)

        if mnem.startswith('mov') or mnem.startswith('cmov'): #mov对寄存器
            # case1: mov reg, imm
            if reg_or_mm_flag and inst.Op2.type == idaapi.o_imm and inst.Op1.type == idaapi.o_reg:
                if str(inst.Op1.reg) == reg_or_mm_t['reg']:
                    FELogger.info("找到赋值点\t" + hexstr(addr) + "\t" + line)
                    return None
            # case2:  mov dest_reg, src_reg
            if reg_or_mm_flag and inst.Op2.type == idaapi.o_reg and inst.Op1.type == idaapi.o_reg:
                if str(inst.Op1.reg) == reg_or_mm_t['reg']:
                    reg_or_mm_t['reg'] = str(inst.Op2.reg)
                    FELogger.info("传播到" + reg_or_mm_t['reg'] + "\t" + hexstr(addr) + "\t" + line)
            # case3:  mov dest_reg, memory
                # memory: o_mem/o_phrase/o_displ
            if reg_or_mm_flag and (inst.Op2.type in [idaapi.o_mem,  idaapi.o_phrase, idaapi.o_displ]) and inst.Op1.type == idaapi.o_reg:
                if str(inst.Op1.reg) == reg_or_mm_t['reg']:
                    if inst.Op2.type == idaapi.o_mem: # data段全局变量
                        FELogger.info("找到赋值点\t" + hexstr(addr) + "\t" + line)
                        return None
                    if inst.Op2.type in [idaapi.o_phrase, idaapi.o_displ]:
                        # 回溯reg转为回溯memory
                        mm_t = get_mm(inst, inst.Op2)
                        reg_or_mm_t['mm'] = mm_t
                        reg_or_mm['reg'] = -1
                        FELogger.info("传播到"+ reg_or_mm_t['mm'] +"\t" + hexstr(addr)+"\t"+line)
            # case4: mov memory, imm
                # memory: o_mem/o_phrase/o_displ
            if (reg_or_mm_flag == 0) and (inst.Op1.type in [idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ]) and inst.Op2.type == idaapi.o_imm:
                mm_t = get_mm(inst, inst.Op1)
                if reg_or_mm_t['mm'] == mm_t:
                    FELogger.info("找到赋值点\t" + hexstr(addr) + "\t" + line)
                    return None
            # case5: mov memory, src_reg
                # memory: o_mem/o_phrase/o_displ
            if (reg_or_mm_flag == 0) and (inst.Op1.type in [idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ]) and inst.Op2.type == idaapi.o_reg:
                mm_t = get_mm(inst, inst.Op1)
                #回溯mem转为回溯reg
                reg_or_mm_t['reg'] = str(inst.Op2.reg)
                reg_or_mm['mm'] = -1
                FELogger.info("传播到" + reg_or_mm_t['reg'] + "\t" + hexstr(addr) + "\t" + line)

        if mnem.startswith('lea'):
            #case 1: lea dest_reg,mem
            # memory: o_mem/o_phrase/o_displ
            if reg_or_mm_flag and (inst.Op2.type in [idaapi.o_mem,  idaapi.o_phrase, idaapi.o_displ]) and inst.Op1.type == idaapi.o_reg:
                if str(inst.Op1.reg) == reg_or_mm_t['reg']:
                    if inst.Op2.type == idaapi.o_mem: # data段全局变量
                        FELogger.info("找到赋值点\t" + hexstr(addr) + "\t" + line)
                        return None
                    elif inst.Op2.type in [idaapi.o_phrase, idaapi.o_displ]:
                        # 回溯reg转为回溯memory
                        mm_t = get_mm(inst, inst.Op2)
                        # lea rsp/rbp,xxx
                        if mm_t[0] == int(RegNo.R_sp) or mm_t[0] == int(RegNo.R_bp):
                            FELogger.info("lea sp, lea rsp/rbp，停止回溯\t" + hexstr(addr) + "\t" + line)
                            return None
                        if mm_t[1] == -1:
                            # case : [reg+68h+var_58]
                            reg_or_mm_t['reg'] = str(mm_t[0])
                            FELogger.info("传播到" + reg_or_mm_t['reg'] + "\t" + hexstr(addr) + "\t" + line)
                        else: # [reg1+reg2 + var_58]
                            #追 reg1
                            FELogger.info("传播到" + str(mm_t[0]) + "\t" + hexstr(addr) + "\t" + line)
                            return {'reg': str(mm_t[0]), 'mm': -1}

        #算术指令
        #xor reg1,reg1 清零操作
        if mnem.startswith('xor') and inst.Op1.type == idaapi.o_reg and inst.Op2.type == idaapi.o_reg and (
                    str(inst.Op1.reg) == str(inst.Op2.reg) == reg_or_mm_t['reg']):
            FELogger.info("找到赋值点\t" + hexstr(addr) + "\t" + line)
            return None
        if mnem.startswith('add') or mnem.startswith('sub') or mnem.startswith('mul') or mnem.startswith('imul') \
            or mnem.startswith('xor') or mnem.startswith('or') or mnem.startswith('and'):
        # xxx reg1,reg2/ reg1, imm
            FELogger.info("传播到" + reg_or_mm_t['reg'] + "\t" + hexstr(addr) + "\t" + line)
        return reg_or_mm_t

    def get_all_ref(self, addr):
        """
        获取所有引用到addr的地址
        """
        xref_t = []
        addr_t = idaapi.get_first_cref_to(addr)
        while addr_t != idaapi.BADADDR:
            xref_t.append(addr_t)
            addr_t = idaapi.get_next_cref_to(addr, addr_t)
        return xref_t

    def get_node_nums(self):
        """
        获取已回溯节点数
        """
        return len(self.cache['all_node'])

    def set_color(self, addr, color_type):
        """
        设置指令背景色
        """
        idaapi.set_item_color(addr, color_type)

    def trace_handle(self, addr, reg_or_mm):
        """
        处理回溯事件
        """
        next_addr = idaapi.prev_head(addr, 0)
        next_reg_or_mm = self.get_next_reg_or_mm(addr, reg_or_mm)

        return (next_addr, next_reg_or_mm)

    def trace_block(self, blk, node, reg_or_mm):
        """
        在一个基本块内回溯
        """
        reg_or_mm_t = reg_or_mm
        cur_t = node['addr']
        #print(blk.start_ea)
        #print(blk.end_ea)
        while reg_or_mm_t and cur_t >= blk.start_ea:
            cur_t, reg_or_mm_t = self.trace_handle(cur_t, reg_or_mm_t)

        return (idaapi.next_head(cur_t, idaapi.BADADDR), reg_or_mm_t)

    def trace_next(self, blk, node, reg):
        """
        下一轮回溯
        """
        for ref_addr in self.get_all_ref(blk.start_ea):
            block = self.get_blk(ref_addr)
            if block:
                FELogger.info("基本块跳转\t"+hexstr(ref_addr)+"\t" +
                              idc.generate_disasm_line(ref_addr, 0))
                node_t = self.create_tree_node(ref_addr, prev=node)
                self.dfs(node_t, reg, block)

    def dfs(self, node, reg_or_mm, blk):
        """深度优先搜索
        node: 当前节点
        reg: 回溯寄存器
        blk: 当前基本块
        """
        blk_t = blk
        if self.get_node_nums() < self.max_node:    # 避免路径爆炸
            if self.push_cache_node(node['addr'], reg_or_mm):  # 避免重复，加快速度
                cur_t, reg_or_mm_t = self.trace_block(blk_t, node, reg_or_mm)
                if reg_or_mm_t:
                    # 如果返回一个新的寄存器或者内存，开启下一轮回溯
                    self.trace_next(blk_t, node, reg_or_mm_t)
                else:
                    self.cache['addr'].add(cur_t)
            # else:
            #     FELogger.info("该块已经回溯，取消操作")
        else:
            FELogger.info("超出最大回溯块数量")

    @FELogger.show_time_cost
    @FELogger.log_time
    def run(self):
        """
        启动回溯
        """
        trace_blk = self.get_blk(self.trace_addr)
        self.dfs(self.tree, self.trace_reg, trace_blk)
        return list(self.cache['addr'])


class FEStrMgr():
    """字符串管理器
    提供获取和解析字符串的功能
    minl: 定义字符串的最短长度
    """

    strings = {}    # 管理器初始化时进行缓存

    def __init__(self, minl=1):
        st_obj = idautils.Strings()
        st_obj.setup(minlen=minl)
        for string in st_obj:
            self.strings[string.ea] = str(string)

    @classmethod
    def get_string_from_mem(cls, addr):
        """
        从addr逐字节获取字符
        """

        string = ''
        chr_t = idaapi.get_wide_byte(addr)
        i = 0
        while chr_t != 0:
            chr_t = idaapi.get_wide_byte(addr+i)
            string += chr(chr_t)
            i += 1
        return string[:-1]

    @classmethod
    def get_mem_string(cls, addr):
        """
        获取内存中的字符串
        """

        addr_t = addr
        dref = idautils.DataRefsFrom(addr_t)
        strs = [cls.strings[x] for x in dref if x in cls.strings]

        # 处理几种特殊情况
        # LDR R1, =sub_xxxx
        # LDR R1, =loc_xxxx
        if idc.print_operand(addr, 1)[:5] in ['=sub_', '=loc_']:
            return []

        # LDR R1, =unk_53B4B6
        # .rodata:0053B4B6 http:
        # .rodata:0053B4BB //%s%s
        if strs != [] and strs[0].find('%') == -1:
            strs = []
            dref = idautils.DataRefsFrom(addr_t)
            for x in dref:
                segname = idaapi.get_segm_name(idaapi.getseg(x))
                if segname not in ['.text', '.bss']:
                    strs.append(cls.get_string_from_mem(x))

        # LDR R1, =(aFailedToGetAnI+0x22)
        # LDR R2, =(aSS - 0xCFA4)
        # ADD R2, PC, R2
        if strs == []:
            dref = idautils.DataRefsFrom(addr_t)
            for x in dref:
                segname = idaapi.get_segm_name(idaapi.getseg(x))
                if segname not in ['.text', '.bss']:
                    strs.append(cls.get_string_from_mem(x))
                elif len(list(idautils.DataRefsFrom(x))) == 0:
                    reg_t = idc.print_operand(addr_t, 0)
                    num1 = idaapi.get_wide_dword(x)
                    while get_mnem(addr_t) != 'ADD' or (idc.print_operand(addr_t, 0) != reg_t and idc.print_operand(addr_t, 1) != 'PC'):
                        addr_t = idaapi.next_head(
                            addr_t, idaapi.BADADDR)
                    num2 = addr_t + 8
                    addr_t = num1 + num2
                    strs.append(cls.get_string_from_mem(addr_t))

        # MOVW R1, #0x87B4
        # MOVT.W R1, #0x52
        if strs == [] and get_mnem(addr_t) == 'MOVW':
            reg_t = idc.print_operand(addr_t, 0)
            num1 = int(idc.print_operand(addr_t, 1).split('#')[1], 16)
            while get_mnem(addr_t) not in ['MOVTGT', 'MOVTLE', 'MOVT'] or idc.print_operand(addr_t, 0) != reg_t:
                addr_t = idaapi.next_head(addr_t, idaapi.BADADDR)
            num2 = int(idc.print_operand(addr_t, 1).split('#')[1], 16)
            addr_t = (num2 << 16) + num1
            strs.append(cls.get_string_from_mem(addr_t))

        return strs

    @classmethod
    def parse_format_string(cls, string):
        """
        解析格式字符串
        %[parameter][flags][field width][.precision][length]type
        """

        _type = ['d', 'i', 'u', 'f', 'F', 'e', 'E', 'g',
                 'G', 'x', 'X', 'o', 's', 'c', 'p', 'a', 'A', 'n']
        pattern = '.*?[%s]' % ''.join(_type)
        fmt_list = string.split("%")[1:]
        results = []
        for fmt in fmt_list:
            re_obj = re.search(pattern, fmt)
            if re_obj:
                results.append(re_obj.group())
        return results


class FEFuncTestForm(ida_kernwin.Form):

    def __init__(self):
        ida_kernwin.Form.__init__(self, """STARTITEM 0
Functional Test
DFS测试（从某地址回溯某寄存器）：
<##测试:{btn_dfs_test_1}>
""", {
            'btn_dfs_test_1': ida_kernwin.Form.ButtonInput(self.btn_dfs_test_1)
        })

    def btn_dfs_test_1(self, code=0):
        addr_t = ida_kernwin.ask_str('', 0, '请输入回溯起点地址')
        reg_t = ida_kernwin.ask_str('', 0, '请输入回溯寄存器')
        if (addr_t and addr_t != '') and (reg_t and reg_t != ''):
            try:
                addr_t = int(addr_t, 16)
            except Exception:
                FELogger.warn("无效地址")
                return

            FELogger.info("从地址%s回溯寄存器%s" % (hexstr(addr_t), reg_t))
            reg_or_mm = {
                'reg': "-1",
                'mm': "-1"
            }
            # reg_or_mm = GetOpnd(addr_t, 1)
            # inst = idautils.DecodeInstruction(addr_t)
            # if inst.Op2.type == idaapi.o_reg:
            #     reg_t['reg'] = str(reg_or_mm)
            # else:
            #     reg_t['mm'] = get_mm(inst, inst.Op2)
            reg_or_mm['reg'] = reg_t
            tracer = FEArgsTracer(addr_t, reg_or_mm)
            source = tracer.run()
            print("source addr ", source)
        else:
            FELogger.warn("请输入起点地址和寄存器")

def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

# 查找函数
def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != idc.BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False

def audit(func_name):
    # 先尝试获取函数
    func_addr = getFuncAddr(func_name)
    if func_addr == False:
        return False
    # 如果获取到了got表位置，尝试解引用到plt表
    if idc.SegName(func_addr) == 'extern':
        func_addr = list(idautils.CodeRefsTo(func_addr, 0))[0]
    for call_addr in idautils.CodeRefsTo(func_addr, 0):
        argv_list = idaapi.get_arg_addrs(call_addr)
        for argv in argv_list:
            reg_t = {
                'reg': "-1",
                'mm': "-1"
            }
            reg_or_mm = GetOpnd(argv, 1)
            inst = idautils.DecodeInstruction(argv)
            if inst.Op2.type == idaapi.o_reg:
                reg_t['reg'] = str(reg_or_mm)
            else:
                reg_t['mm'] = get_mm(inst, inst.Op2)
            tracer = FEArgsTracer(argv, reg_t, max_node=256)
            source = tracer.run()
            print("source addr ", [hex(i) for i in source])


if __name__ == '__main__':
    start = '''
     ____        _   ____        _ 
    |  _ \ _   _(_) |  _ \ _   _(_)
    | |_) | | | | | | |_) | | | | |
    |  _ <| |_| | | |  _ <| |_| | |
    |_| \_\\__,_|_| |_| \_\\__,_|_|
    '''
    print(start)

    main = FEFuncTestForm()
    main.Compile()
    main.Execute()

    print("Finished! Enjoy the result ~")