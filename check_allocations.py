import binaryninja
import sys
import os

def get_previous_block(bv: binaryninja.BinaryViewType, block: binaryninja.lowlevelil.LowLevelILBasicBlock):
    addr = block[0].address
    try: bb = bv.get_basic_blocks_starting_at(addr)[0]
    except: return None
    incoming = bb.incoming_edges
    if len(incoming) > 1:
        print(">1 incoming branches, investigate manually ( " + hex(addr) + " )")
        return None
    elif len(incoming) == 0:
        # print("Exhausted preceding blocks")
        return None
    start = incoming[0].source.start
    func = bv.get_functions_containing(start)[0]
    for block in func.llil:
        if block[0].address == start:
            return block
    return None

def find_register_value (bv: binaryninja.BinaryViewType, 
    block: binaryninja.lowlevelil.LowLevelILBasicBlock, 
    reg: str, call_addr: int, index: int):

    operations = [binaryninja.lowlevelil.LowLevelILAdd, 
        binaryninja.lowlevelil.LowLevelILMul]

    # iterate backward in LLIL basic blocks
    while index >= 0 and block is not None:
        if block[index].operation == binaryninja.LowLevelILOperation.LLIL_SET_REG and \
            str(block[index].dest) == reg:
            # print(block[index], block[index].operation, type(block[index].src))
            
            # if the rhs is the result of + or * then return it
            if type(block[index].src) in operations:
                return block[index].src

            # else if the register is assigned from another register then find it
            elif type(block[index].src) == binaryninja.lowlevelil.LowLevelILReg:
                reg = str(block[index].src)
                # print("new register " + reg)

        index -= 1

        # if we exhausted the basic block, check preceding blocks
        if index < 0:
            block = get_previous_block(bv, block)
            if block is not None: index = len(block) - 1
            else: return None


def process_calling_function(bv: binaryninja.BinaryViewType,
    caller_addr: int, reg: str, alloc_addr: int, function_addrs: tuple):
    
    calling_funcs = set()
    malloc_addr, calloc_addr, realloc_addr = function_addrs

    for func in bv.functions:   # iterate through all functions
        for bb in func.llil:    # iterate through each LLIL logical basic block
            for index, instr in enumerate(bb):    # iterate through "instructions" 
                if (instr.operation == binaryninja.LowLevelILOperation.LLIL_CALL \
                or instr.operation == binaryninja.LowLevelILOperation.LLIL_CALL_STACK_ADJUST) \
                and type(instr.dest) == binaryninja.lowlevelil.LowLevelILConstPtr \
                and instr.dest.value.value == caller_addr: # if operation is a call to the calling func
                    if reg == "rdi": size = instr.get_reg_value("rdi")
                    else:               size = instr.get_reg_value("rsi")

                    # check if variable length argument (undetermined variable value)
                    if type(size) == binaryninja.variable.Undetermined:
                        val = find_register_value(bv, bb, reg, instr.address, index)
                        if val is not None:
                            print("match found ( " + hex(instr.address) + " ): " + \
                                bv.get_function_at(caller_addr).name + "( ", end = "")
                            print(val, ")")   

def check_allocations(bv: binaryninja.BinaryViewType):
    calling_funcs = set()
    malloc_addr = 0
    calloc_addr = 0
    realloc_addr = 0
    for func in bv.functions:   # get function addresses for heap allocation calls
        if func.name == "malloc":    malloc_addr  = func.start
        elif func.name == "calloc":  calloc_addr  = func.start
        elif func.name == "realloc": realloc_addr = func.start

    function_addrs = set({malloc_addr, calloc_addr, realloc_addr})
    try: function_addrs.remove(0)
    except: pass
    
    for func in bv.functions:   # iterate through all functions
        for bb in func.llil:    # iterate through each LLIL logical basic block
            for index, instr in enumerate(bb):    # iterate through "instructions" 
                if (instr.operation == binaryninja.LowLevelILOperation.LLIL_CALL \
                or instr.operation == binaryninja.LowLevelILOperation.LLIL_CALL_STACK_ADJUST) \
                and type(instr.dest) == binaryninja.lowlevelil.LowLevelILConstPtr \
                and instr.dest.value.value in function_addrs: # if operation is a call to one of our functions
                    # grab appropriate size argument (rdi for malloc, rsi for calloc, realloc)
                    target = ""
                    if instr.dest.value.value == malloc_addr: 
                        size = instr.get_reg_value("rdi")
                        target = "rdi"
                    else: 
                        size = instr.get_reg_value("rsi")
                        target = "rsi"
                    # check if called with parent "wrapper" function argument (e.g., malloc(arg1))
                    if type(size) == binaryninja.variable.EntryRegisterValue: 
                        calling_reg = size.reg
                        calling_funcs.add((func.start, calling_reg, instr.dest.value.value))
                    # check if variable length argument (undetermined variable value)
                    elif type(size) == binaryninja.variable.Undetermined:
                        val = find_register_value(bv, bb, target, instr.address, index)
                        if val is not None:
                            print("match found ( " + hex(instr.address) + " ): ", end = "")
                            if instr.dest.value.value ==   malloc_addr:  print(" malloc(", end = " ") 
                            elif instr.dest.value.value == calloc_addr:  print(" calloc(", end = " ") 
                            elif instr.dest.value.value == realloc_addr: print("realloc(", end = " ") 
                            print(val, ")")

    # check any "wrapper" functions for variable length arguments passed to our functions, e.g.:
    '''
        malloc_wrapper(int x) {
            x = x = 1;
            return malloc(x);
        }
    '''
    print("\nHandling wrapper functions")
    for caller_addr, target, alloc_addr in calling_funcs: 
        process_calling_function(bv, caller_addr, target, alloc_addr,
        (malloc_addr, calloc_addr, realloc_addr))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error. Usage: python3 check_allocations.py <filename>")
        exit(1)

    # open a BinaryView of the target binary file
    filename = sys.argv[1]
    bv = None
    try:
        bv = binaryninja.BinaryViewType.get_view_of_file(filename)
        if bv == None:
            exit(0), "Error. Failed to create Binary Ninja database for target."
        bv.create_database(filename)
    except Exception as e:
        print(e)

    check_allocations(bv)