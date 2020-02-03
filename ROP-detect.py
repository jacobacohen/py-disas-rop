from capstone import *
import capstone.x86 as x86
import capstone.x86_const as x86_const
from bfdpie import *
import argparse
import IPython
import pefile

# TODO: Error checking

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Name of binary to read",
                        type=str, required=True)

    # TODO: PE format fixing
    args = parser.parse_args()

    bin_text = Binary(args.file)
    bit_ver = bin_text.arch.bits
    sect_stack = []
    # get executable sections
    for i,j in bin_text.sections.iteritems():
        if j.flags & bfdpie.SEC_CODE:
            sect_stack.append(j)

    x86_opc_ret = '\xc3'
    max_gadget_len = 5
    
    gadget_dicts = [{}] * len(sect_stack)
    # init capstone, turn extra detail on
    mode = CS_MODE_32 if bit_ver == 32 else CS_MODE_64
    # elf or coff (win)
    file_type = bin_text.file_type
    cap = Cs(CS_ARCH_X86, mode)
    cap.detail = True
    if file_type == "coff":
        # from some Stack Overflow post
        pe = pefile.PE(args.file)
        eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code_sect = pe.get_section_by_rva(eop)
        code_dump = code_sect.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + code_sect.VirtualAddress
        # clear wrong(?) other sections
        sect_stack = []
        # have only the code section
        # still doesn't work, oh well
        sect_stack.append(code_dump)
    else:
        #IPython.embed()
        # keeps track of visited addresses
        visited = []

        # main gadget search loop
        # i is to keep track of which
        i = 0
        for sect in sect_stack:
            #IPython.embed()
            for j, ins in enumerate(sect.contents):
                if ins == x86_opc_ret:
                    # add vma to i to get real address
                    #IPython.embed()
                    at_root = find_gadget_at_root(sect, sect.vma + long(j), cap)
                    if at_root != {}:
                        gadget_dicts[i] = at_root
            i += 1
        print_gadget_dict(gadget_dicts)


def find_gadget_at_root(sect, root, cap):
    gadgets = {}
    max_gadget_len = 5
    x86_max_ins_bytes = 15
    root_offset = max_gadget_len * x86_max_ins_bytes
    a = root - 1
    a_ret = 0
    # work up to root address
    while a >= root-root_offset and a >= 0:
        addr = a
        offset = addr - sect.vma
        pc = sect.vma + offset
        n = sect.size - offset
        len = 0
        gadget_str = ''
        for ins in cap.disasm(sect.contents, pc):
            len += 1
            #IPython.embed()
            # instruction break cases
            if ins.id == x86.X86_INS_INVALID or ins.size == 0:
                break
            elif ins.address > root:
                break
            elif is_cs_cflow_ins(ins) and not is_cs_ret_ins(ins):
                break
            elif len > max_gadget_len:
                break
            gadget_str += ins.mnemonic + " " + ins.op_str
            # back to root (ret)
            if ins.address == root:
                a_ret = a
                gadget_str += "; ret;"
                if gadget_str in gadgets:
                    gadgets[gadget_str].append(hex(a_ret)[:-1])
                else:
                    gadgets[gadget_str] = [hex(a_ret)[:-1]]
                break
            gadget_str += "; "
        a -= 1
    # add to gadgets
    return gadgets


def print_gadget_dict(gadget_dicts):
    final_dict = {}
    # loop to collect all values
    for dict in gadget_dicts:
        for gd, addresses in dict.iteritems():
            if gd in final_dict:
                final_dict[gd] += addresses
            else:
                final_dict[gd] = addresses
    # print for real
    for gd, addresses in final_dict.iteritems():
        print("%s\t%s" % (addresses, gd))
    return


def is_cs_cflow_group(g):
    return g == x86.X86_GRP_JUMP or g == x86.X86_INS_CALL or \
           g == x86.X86_INS_RET or g == x86.X86_INS_IRET


def is_cs_cflow_ins(ins):
    for grp in ins.groups:
        if is_cs_cflow_group(grp):
            return True
    return False


def is_cs_ret_ins(ins):
    return ins.id == x86.X86_INS_RET


if __name__ == "__main__":
    main()
