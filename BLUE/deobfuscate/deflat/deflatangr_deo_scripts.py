
# 去除x86指令集二进制文件平坦流
# 参考：
# https://security.tencent.com/index.php/blog/msg/112
# https://docs.angr.io/core-concepts
# https://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html
# https://github.com/cq674350529/deflat/tree/a210659bd4b3912d9ac2dd99eec17e417db3a8ef/flat_control_flow

import angr
import pyvex
import argparse
import convert_to_ida_graph
import claripy
import struct

opcode = {'a':b'\x87', 'ae':b'\x83', 'b':b'\x82', 'be':b'\x86', 'c':b'\x82', 'e':b'\x84', 'z':b'\x84', 'g':b'\x8F',   'ge':b'\x8D', 'l':b'\x8C', 'le':b'\x8E', 'na':b'\x86', 'nae':b'\x82', 'nb':b'\x83', 'nbe':b'\x87', 'nc':b'\x83',  'ne':b'\x85', 'ng':b'\x8E', 'nge':b'\x8C', 'nl':b'\x8D', 'nle':b'\x8F', 'no':b'\x81', 'np':b'\x8B', 'ns':b'\x89',  'nz':b'\x85', 'o':b'\x80', 'p':b'\x8A', 'pe':b'\x8A', 'po':b'\x8B', 's':b'\x88', 'nop':b'\x90', 'jmp':b'\xE9', 'j':b'\x0F'}

def patch_instruction(data, offset, patchbytes):
    data[offset:offset + len(patchbytes)] = list[patchbytes]

def fill_nops(data, offset, size):
    data[offset:offset+size] = [90] * size


def symbolic_execute(proj, nodeAddr, releNodesAddrs, hookAddrs, modifyVal=None, inspect=False):
    def statement_inspect(state):
        exprs = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(exprs)!=0 and isinstance(exprs[0], pyvex.expr.ITE):
            state.scratch.temps[exprs[0].cond.tmp] = modifyVal
            state.inspect._breakpoints['statement'] = []

    def retn_procedure(state):
        ip = state.solver.eval(state.regs.ip)
        b.unhook(ip)
        return

    if hookAddrs:
        for addr in hookAddrs:
            proj.hook(addr, hook = retn_procedure, length=5)
    st = proj.factory.blank_state(addr = nodeAddr, remove_options={angr.options.LAZY_SOLVES})
    if inspect and modifyVal != None:
        st.inspect.b('statement', when=angr.BP_BEFORE, action=statement_inspect)
    simgr = proj.factory.simgr(st)
    simgr.step()
    while len(simgr.active) > 0:
        for act in simgr.active:
            if act.addr in releNodesAddrs:
                return act.addr
        simgr.step()
    return None

def main():
    parser = argparse.ArgumentParser(description='Deflat script for flatted binary file.')
    parser.add_argument('Filename', help = 'filename to be deflat.')
    parser.add_argument('Address', help = 'address in the binary to be deflat')

    args = parser.parse_args()
    filename = args.Filename        # 目标二进制文件
    addr = int(args.Address, 16)    # 处理函数地址

    proj = angr.Project(filename, load_options={'auto_load_libs':False})
    cfg = proj.analyses.CFGFast(normalize=True)
    targetFuncAddr = cfg.functions.get(addr)
    supergraph = convert_to_ida_graph.to_supergraph(deflatFunc.transition_graph)
    
    for node in supergraph.nodes:
        if node.addr == targetFuncAddr and 0 == supergraph.in_degree(node):
            prologueNode = node
        if 0 == len(node.out_branches) and 0 == supergraph.out_degree(node):
            retNode = node

    mainDisptchNode = list(supergraph.successors(prologueNode))[0]
    for node in supergraph.predecessors(mainDisptchNode):
        if node.addr != prologueNode.addr:
            preDispatchNode = node
    
    relevantNodes = []
    nopsNodes = []
    for node in supergraph.nodes:
        succNodes = list(supergraph.successors(node))
        if 1 == len(succNodes) and retNode.addr == succNodes[0].addr and node.cfg_nodes[0].size > 5:
            relevantNodes.append(node)
        elif node.addr not in (prologueNode.addr, retNode.addr, mainDisptchNode.addr, preDispatchNode.addr):
            nopsNodes.append(node)

    print('*******************relevant blocks************************')
    print('prologue:%#x' % prologueNode.addr)
    print('main_dispatcher:%#x' % mainDisptchNode.addr)
    print('pre_dispatcher:%#x' % preDispatchNode.addr)
    print('retn:%#x' % retNode.addr)
    print('relevant_blocks:', [hex(node.addr) for node in relevantNodes])

    print('*******************symbolic execution*********************')

    relevantNodes.append(prologueNode)
    relevantNodesWithRet = relevantNodes + [retNode]
    relevantNodesWithRet_Addrs = [node.addr for node in relevantNodesWithRet]

    flows = {}
    patchInsns = {}
    for node in relevantNodes:
        flows[node] = []
        insns = proj.factory.block(node.addr, size = node.size).capstone.insns
        hookAddrs = []
        hasBraches = False
        for ins in insns:
            if ins.mnemonic.startswith('cmov'):
                patchInsns[node.addr] = ins.address
                hasBraches = True
            elif ins.mnemonic.startswith('call'):
                hookAddrs.append(ins.address)
        if hasBraches:
            tmpAddr = None
            tmpAddr = symbolic_execute(proj, node.addr, relevantNodesWithRet_Addrs, hookAddrs, claripy.BVV(1, 1), True)
            if tmpAddr:
                flows[node].append(tmpAddr)

            tmpAddr = None
            tmpAddr = symbolic_execute(proj, node.addr, relevantNodesWithRet_Addrs, hookAddrs, claripy.BVV(0, 1), True)
            if tmpAddr:
                flows[node].append(tmpAddr)

        else:
            tmpAddr = None
            tmpAddr = symbolic_execute(proj, node.addr, relevantNodesWithRet_Addrs, hookAddrs)
            if tmpAddr:
                flows[node.addr].append(tmpAddr)
    print('************************flow******************************')
    for k, v in flows.items():
        print('%#x: ' % k, [hex(child) for child in v])
    print('%#x: ' % retNode.addr, [])

    print('************************patch*****************************')
    baseAddr = p.loader.main_object.mapped_base >> 12 << 12
    fin = open(filename, 'rb')
    originData = list(fin.read())
    originData_len = len(originData)
    fin.close()
    for node in nopsNodes:
        fill_nops(originData, node.addr - baseAddr, node.size)
    for parent,childs in flows.items():
        if 1 == len(childs):
            last_insn = proj.factory.block(parent.addr, size = parent.size).capstone.insns[-1]
            file_offset = last_insn.addr - baseAddr
            fill_nops(originData, last_insn.address, last_insn.size)
            patch_instruction(originData, file_offset, opcode['jmp'] + struct.pack('<i', childs[0] - last_instr.address - 5))

        else:
            insn = patchInsns[parent.addr]
            file_offset = insn.addr - baseAddr
            fill_nops(originData, fileoffset, parent.addr + parent.size - insn.address)
            patch_instruction(originData, file_offset, opcode['j'] + opcode[insn.mnemonic[len('cmov'):]] + struct.pack('<i', childs[0] - insn.address - 6))

            file_offset += 6
            patch_instruction(originData, file_offset, opcode['jmp'] + struct.pack('<i', childs[1] - (insn.address + 6) - 5))

        if len(originData) != originData_len:
            print('ERROR : Final File DATA size don\'t match!!!')

        fo = open(filename + '.recovered', 'wb')
        fo.write(b''.join(bytes([c]) for c in originData))
        fo.close()

        print('FINISH...')

if __name__ == "__main__":
    main()
