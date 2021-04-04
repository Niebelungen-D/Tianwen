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