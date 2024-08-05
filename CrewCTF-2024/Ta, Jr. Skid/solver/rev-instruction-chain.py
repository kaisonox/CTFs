

out = open('rev-instruction-chain.asm.asm', 'w')

inp = open('instruction-chain.asm.asm', 'r')

# ['pshufb', 'psubq', 'psubw', 'psubd', 'pxor', 'paddq', 'psubb', 'paddd', 'paddw', 'paddb']

for line in inp.readlines()[::-1]:
    ins, opers = line.split(' ', 1)
    if ins == 'pshufb':
        # pshufb  xmm0, xmmword ptr [r15+1630h]
        out.write(f'pshufb {opers}')
    elif ins == 'psubq':
        out.write(f'paddq {opers}')
    elif ins == 'psubw':
        out.write(f'paddw {opers}')
    elif ins == 'psubd':
        out.write(f'paddd {opers}')
    elif ins == 'pxor':
        out.write(f'pxor {opers}')
    elif ins == 'paddq':
        out.write(f'psubq {opers}')
    elif ins == 'psubb':
        out.write(f'paddb {opers}')
    elif ins == 'paddd':
        out.write(f'psubd {opers}')
    elif ins == 'paddw':
        out.write(f'psubw {opers}')
    elif ins == 'paddb':
        out.write(f'psubb {opers}')
    else:
        out.write(line)


