from capstone import *
import capstone.x86 as x86
import capstone.x86_const as x86_const
from bfdpie import *
import monkeyhex
import binascii
import argparse
import IPython

# TODO: Error checking

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Name of binary to read",
                        type=str, required=True)

    args = parser.parse_args()

    bin_text = Binary(args.file)

    # get executable sections
    for i,j in bin_text.sections.iteritems():
        if j.flags & bfdpie.SEC_CODE:
            # disassemble section at a time
            rec_disassemble(j)


def rec_disassemble(sect):
    stack = []
    sect_len = sect.size
    sect_start = sect.vma
    sect_contents = sect.contents
    exec_area = range(sect_start, sect_start + sect_len)
    # init capstone, turn extra detail on
    cap = Cs(CS_ARCH_X86, CS_MODE_32)
    cap.detail = True

    '''file_contents = bytearray()
    # get full text in hex (for use with symbols)
    with open(args.file, "r") as open_file:
        for byte in open_file.read():
            file_contents.append(byte)'''

    # keeps track of visited addresses
    visited = []
    # append entry point to stack
    stack.append(sect_start)
    # main DFS loop
    while stack != []:
        cur = stack.pop()
        location = cur
        offset = sect_start - location
        if location not in visited:
            visited.append(location)
            # codepoint = cur.contents if isinstance(cur, Section) else file_contents
            for ins in cap.disasm(sect_contents, location):
                if ins.id == x86.X86_INS_INVALID or ins.size == 0:
                    break
                # mark address as seen
                visited.append(ins.address)
                ins_print(ins)
                #IPython.embed()
                if is_cs_cflow_ins(ins):
                    target = long(get_cs_ins_immediate_target(ins))
                    # TODO: If executable section add
                    if target != 0 and target not in visited and sect_start < target < sect_len:
                        stack.append(target)
                        print(" -> new target: 0x%x" % target)
                    if is_cs_unconditional_cflow_ins(ins):
                        break
                elif ins.id == x86.X86_INS_HLT:
                    break
            print("-------")


def entry_print(vma):
    print("Entry point: 0x%x" % vma)
    return


def ins_print(ins):
    print("0x%x\t%s\t\t%s\t%s" % (ins.address, binascii.hexlify(ins.bytes), ins.mnemonic, ins.op_str))
    return


def function_print(vma):
    print("function symbol: 0x%x" % vma)
    return


def is_cs_cflow_group(g):
    return g == x86.X86_GRP_JUMP or g == x86.X86_INS_CALL or \
           g == x86.X86_INS_RET or g == x86.X86_INS_IRET


def is_cs_cflow_ins(ins):
    for i in range(0, len(ins.groups)):
        return is_cs_cflow_group(i)


def is_cs_unconditional_cflow_ins(ins):
    return ins.id == x86.X86_INS_JMP or ins.id == x86.X86_INS_LJMP or \
     ins.id == x86.X86_INS_RET or ins.id == x86.X86_INS_RETF or \
     ins.id == x86.X86_INS_RETFQ


def get_cs_ins_immediate_target(ins):
    i = 0
    j = 0
    while i < len(ins.groups):
        if is_cs_cflow_group(ins.groups[i]):
            while j < len(ins.opcode) and j < len(ins.operands):
                cs_op = ins.operands[j]
                if cs_op.type == x86.X86_OP_IMM:
                    return cs_op.imm
                j += 1
        i += 1
    return 0


if __name__ == "__main__":
    main()

