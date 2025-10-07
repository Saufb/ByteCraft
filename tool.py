#!/usr/bin/env python3
"""ByteCraft 
Author: I'm the developer Casper — I've written this tool to teach and experiment safely with x86_64 assembly.

Features (implemented):
- assemble (Keystone), disassemble (Capstone), emulate (Unicorn)
- interactive step execution (inspect, next, continue, set regs, undo last step)
- memory watchpoints (stop when watched addresses change)
- flags tracking and display per instruction (ZF, CF, OF, SF, PF)
- instruction logging (CSV/JSON) with registers+flags per executed instruction
- function call/return trace
- multi-file inputs and inline assembly
- safety: blocks 'syscall' opcode unless --allow-syscalls
- memory inspection of data region and stack top
- breakpoint support by instruction index
- written in a personal, first-person tone in README and comments

Note: This tool is educational. Do NOT emulate untrusted code without understanding it.
"""

import sys, os, argparse, csv, json, time
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import *

PAGE_ADDR = 0x1000000
PAGE_SIZE = 4 * 1024 * 1024  # 4MB mapped for code+data+stack
SNAPSHOT_MEM = 4096  # bytes to snapshot around areas for undo

# simple comments for some mnemonics
COMMENT_MAP = {
    'mov': 'move data',
    'add': 'add values',
    'sub': 'subtract values',
    'imul': 'multiply signed',
    'xor': 'xor (often zero reg)',
    'lea': 'load effective address',
    'push': 'push to stack',
    'pop': 'pop from stack',
    'call': 'function call',
    'ret': 'return from function',
    'cmp': 'compare (affects flags)',
    'jne': 'jump if not equal',
    'jl': 'jump if less (signed)',
    'jmp': 'unconditional jump',
    'nop': 'no-op',
}

def assemble(text):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(text)
    return bytes(encoding)

def disasm(code_bytes, base=0x1000):
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = False
    out = []
    for i in cs.disasm(code_bytes, base):
        out.append((i.address, i.mnemonic, i.op_str, i.bytes))
    return out

def contains_syscall(code_bytes):
    return b'\x0f\x05' in code_bytes

def decode_flags(eflags):
    return {
        'CF': (eflags >> 0) & 1,
        'PF': (eflags >> 2) & 1,
        'AF': (eflags >> 4) & 1,
        'ZF': (eflags >> 6) & 1,
        'SF': (eflags >> 7) & 1,
        'OF': (eflags >> 11) & 1,
    }

class EmulatorSession:
    def __init__(self, code_bytes, steps=200, mem_dump=64, allow_syscall=False):
        self.code = code_bytes
        self.steps = steps
        self.mem_dump = mem_dump
        self.allow_syscall = allow_syscall
        self.mu = None
        self.call_trace = []
        self.watchpoints = {}  # addr -> (length, last_bytes)
        self.log = []  # executed instruction records
        self.snapshots = []  # for undo (store tuples of regs + mem segments)
        self.instr_count = 0
        self.stop_reason = None
        self.hooks = []

    def setup(self):
        if contains_syscall(self.code) and not self.allow_syscall:
            raise RuntimeError("Refusing to emulate: 'syscall' found. Use --allow-syscalls to override.")
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(PAGE_ADDR, PAGE_SIZE)
        mu.mem_write(PAGE_ADDR, self.code)
        # set stack near top
        stack_top = PAGE_ADDR + PAGE_SIZE - 0x1000
        mu.reg_write(UC_X86_REG_RSP, stack_top)
        mu.reg_write(UC_X86_REG_RIP, PAGE_ADDR)
        # init some regs
        mu.reg_write(UC_X86_REG_RAX, 0x0)
        mu.reg_write(UC_X86_REG_RBX, 0x1111)
        mu.reg_write(UC_X86_REG_RCX, 0x2222)
        mu.reg_write(UC_X86_REG_RDX, 0x3333)
        self.mu = mu
        self.instr_count = 0
        self.stop_reason = None
        # code hook
        def hook_code(uc, address, size, user_data):
            idx = self.instr_count
            # snapshot before executing instruction for possible undo
            self._push_snapshot()
            # check breakpoints - handled externally by returning control
            self.instr_count += 1
        self.hooks.append(mu.hook_add(UC_HOOK_CODE, hook_code))
        # return hook to catch invalid memory etc
        def hook_intr(uc, intno, user_data):
            self.stop_reason = ('interrupt', intno)
            uc.emu_stop()
        self.hooks.append(mu.hook_add(UC_HOOK_INTR, hook_intr))

    def _push_snapshot(self):
        # capture registers and small memory around stack top and code end
        try:
            regs = {r: self.mu.reg_read(getattr(UC_X86_REG, r)) for r in ['RAX','RBX','RCX','RDX','RSP','RIP','RBP']}
        except Exception:
            regs = {}
        # memory snapshot: stack region and code end region
        try:
            rsp = regs.get('RSP', PAGE_ADDR + PAGE_SIZE - 0x1000)
            stack_bytes = self.mu.mem_read(max(PAGE_ADDR, rsp - SNAPSHOT_MEM//2), SNAPSHOT_MEM)
        except Exception:
            stack_bytes = b''
        try:
            code_end = PAGE_ADDR + len(self.code)
            data_bytes = self.mu.mem_read(code_end, SNAPSHOT_MEM)
        except Exception:
            data_bytes = b''
        self.snapshots.append((regs, stack_bytes, data_bytes))
        # limit snapshots to avoid memory growth
        if len(self.snapshots) > 64:
            self.snapshots.pop(0)

    def undo_last(self):
        if not self.snapshots:
            print('[undo] no snapshot available')
            return False
        regs, stack_bytes, data_bytes = self.snapshots.pop()
        # restore regs
        for r,v in regs.items():
            try:
                self.mu.reg_write(getattr(UC_X86_REG, r), v)
            except Exception:
                pass
        # restore memory: stack and data
        try:
            rsp = regs.get('RSP', PAGE_ADDR + PAGE_SIZE - 0x1000)
            self.mu.mem_write(max(PAGE_ADDR, rsp - SNAPSHOT_MEM//2), stack_bytes)
        except Exception:
            pass
        try:
            code_end = PAGE_ADDR + len(self.code)
            self.mu.mem_write(code_end, data_bytes)
        except Exception:
            pass
        print('[undo] restored previous snapshot (registers + nearby memory)')
        return True

    def add_watch(self, addr, length=8):
        try:
            b = self.mu.mem_read(addr, length)
            self.watchpoints[addr] = (length, b)
            print(f'[watch] added: 0x{addr:x} len={length}')
        except Exception as e:
            print('[watch] failed to add watch:', e)

    def check_watches(self):
        for addr, (length, last) in list(self.watchpoints.items()):
            try:
                cur = self.mu.mem_read(addr, length)
            except Exception:
                cur = None
            if cur is None:
                continue
            if cur != last:
                self.stop_reason = ('watchpoint', addr)
                # update stored value
                self.watchpoints[addr] = (length, cur)
                self.mu.emu_stop()
                return True
        return False

    def log_instruction(self, idx, addr, mnem, ops):
        # capture regs & flags
        try:
            regs = { 'RAX': self.mu.reg_read(UC_X86_REG_RAX),
                     'RBX': self.mu.reg_read(UC_X86_REG_RBX),
                     'RCX': self.mu.reg_read(UC_X86_REG_RCX),
                     'RDX': self.mu.reg_read(UC_X86_REG_RDX),
                     'RSP': self.mu.reg_read(UC_X86_REG_RSP),
                     'RIP': self.mu.reg_read(UC_X86_REG_RIP),
                     'EFLAGS': self.mu.reg_read(UC_X86_REG_EFLAGS) & 0xffffffff }
        except Exception:
            regs = {}
        flags = decode_flags(regs.get('EFLAGS',0))
        rec = {'idx': idx, 'addr': addr, 'mnemonic': mnem, 'op_str': ops, 'regs': regs, 'flags': flags, 'time': time.time()}
        self.log.append(rec)

    def run_to_completion(self, disasm_list, max_steps=None, interactive=False, breakpoints=None):
        if self.mu is None:
            self.setup()
        max_steps = max_steps or self.steps
        # We'll drive execution by manually stepping instruction-by-instruction using hooks and emu_start with count=1 repeatedly
        executed = 0
        idx = 0
        try:
            while executed < max_steps:
                # single-step: run 1 instruction
                try:
                    self.mu.emu_start(self.mu.reg_read(UC_X86_REG_RIP), PAGE_ADDR + len(self.code), timeout=0, count=1)
                except Exception as e:
                    # emu_stop will raise, so continue to inspect state
                    pass
                rip = self.mu.reg_read(UC_X86_REG_RIP)
                # find instruction at RIP from disasm_list by address
                found = None
                for i,(addr,mnem,ops,bts) in enumerate(disasm_list):
                    if addr == rip:
                        found = (i,addr,mnem,ops)
                        break
                    # sometimes RIP points inside next instr; skip
                # fallback: pick next instruction by executed count
                if found is None and executed < len(disasm_list):
                    found = (executed, disasm_list[executed][0], disasm_list[executed][1], disasm_list[executed][2])
                if found:
                    i, addr, mnem, ops = found
                else:
                    i, addr, mnem, ops = executed, rip, '<unknown>', ''
                # log
                self.log_instruction(i, addr, mnem, ops)
                executed += 1
                # check watches
                if self.check_watches():
                    print(f'[watchpoint] memory changed at 0x{self.stop_reason[1]:x} — stopping')
                    break
                # interactive prompt
                if interactive:
                    print(f"STEP {executed-1} @0x{addr:x}: {mnem} {ops}") 
                    regs = { 'RAX': self.mu.reg_read(UC_X86_REG_RAX),
                             'RBX': self.mu.reg_read(UC_X86_REG_RBX),
                             'RCX': self.mu.reg_read(UC_X86_REG_RCX),
                             'RDX': self.mu.reg_read(UC_X86_REG_RDX),
                             'RSP': self.mu.reg_read(UC_X86_REG_RSP),
                             'RIP': self.mu.reg_read(UC_X86_REG_RIP),
                             'EFLAGS': self.mu.reg_read(UC_X86_REG_EFLAGS) & 0xffffffff }
                    print(' regs: RAX=0x{RAX:x} RBX=0x{RBX:x} RCX=0x{RCX:x} RDX=0x{RDX:x} RSP=0x{RSP:x} RIP=0x{RIP:x}'.format(**regs))
                    print(' flags:', decode_flags(regs['EFLAGS']))
                    cmd = input("(n)ext, (c)ontinue, (u)ndo, (p)oke reg (eg 'p RAX 0x10'), (w)atch (addr,len), (s)ave-log, (q)uit > ").strip()
                    if cmd == 'n' or cmd == '':
                        pass
                    elif cmd == 'c':
                        # run remaining without interactive until finish or breakpoint/watch
                        interactive = False
                    elif cmd == 'u':
                        self.undo_last()
                    elif cmd.startswith('p '):
                        parts = cmd.split()
                        if len(parts) >= 3:
                            reg = parts[1].upper()
                            val = int(parts[2],0)
                            try:
                                self.mu.reg_write(getattr(UC_X86_REG, reg), val)
                                print(f'[poke] set {reg} = 0x{val:x}')
                            except Exception as e:
                                print('[poke] failed:', e)
                    elif cmd.startswith('w '):
                        try:
                            parts = cmd.split()
                            a = int(parts[1],0)
                            l = int(parts[2],0) if len(parts)>2 else 8
                            self.add_watch(a,l)
                        except Exception as e:
                            print('[watch] bad input', e)
                    elif cmd.startswith('s'):
                        fname = cmd.split()[1] if len(cmd.split())>1 else 'bytecraft_log.json'
                        try:
                            with open(fname,'w') as f:
                                json.dump(self.log, f, indent=2)
                            print('[save] log written to', fname)
                        except Exception as e:
                            print('[save] failed', e)
                    elif cmd == 'q':
                        self.stop_reason = ('user',)
                        break
                    else:
                        print('[?] unknown cmd')
                # simple call/ret trace handling
                if mnem == 'call':
                    # push target address to call_trace (approx)
                    try:
                        # op may be label or imm
                        if ops.startswith('0x'):
                            self.call_trace.append(int(ops.split()[0],0))
                        else:
                            self.call_trace.append(ops)
                    except Exception:
                        self.call_trace.append(ops)
                elif mnem == 'ret':
                    if self.call_trace:
                        self.call_trace.pop()
                # breakpoint by index
                if breakpoints and (i in breakpoints):
                    self.stop_reason = ('breakpoint', i)
                    print(f'[breakpoint] hit at index {i}')
                    break
            return executed
        except KeyboardInterrupt:
            self.stop_reason = ('keyboard',)
            return executed

def read_sources(file_list, inline):
    parts = []
    if file_list:
        for f in file_list:
            with open(f,'r') as fh:
                parts.append(fh.read())
    if inline:
        parts.append(inline)
    return '\n\n'.join(parts)

def main():
    ap = argparse.ArgumentParser(prog='ByteCraft', description='ByteCraft v2 - interactive assembler/emulator (x86_64). I wrote this to teach and experiment.')
    ap.add_argument('-f','--files', action='append', help='assembly source file(s)', metavar='FILE')
    ap.add_argument('-e','--inline', help='inline assembly', metavar='CODE')
    ap.add_argument('-s','--steps', type=int, default=500, help='max instructions to execute')
    ap.add_argument('--base','-b', type=lambda x:int(x,0), default=0x1000, help='base address for disasm')
    ap.add_argument('--no-emulate', action='store_true', help='assemble/disasm only')
    ap.add_argument('--allow-syscalls', action='store_true', help='allow syscall opcode (unsafe)')
    ap.add_argument('--interactive','-i', action='store_true', help='enter interactive step mode')
    ap.add_argument('--breakpoints', help='comma list of instruction indexes to break on')
    ap.add_argument('--mem-dump', type=int, default=64, help='bytes to dump for memory views')
    ap.add_argument('--watch', help='add a watchpoint addr:length (hex or dec), e.g. 0x601000:8')
    ap.add_argument('--save-json', help='save execution log as JSON (file path)')
    ap.add_argument('--save-csv', help='save execution log as CSV (file path)')
    args = ap.parse_args()

    if not args.files and not args.inline:
        ap.error('No input provided. Use -f or -e')
    src = read_sources(args.files, args.inline)
    print('--- source ---\n', src)
    try:
        code = assemble(src)
    except Exception as e:
        print('[error] assemble failed:', e); sys.exit(1)
    print('\n--- bytes (hex) ---\n', code.hex())
    dis = disasm(code, base=args.base)
    print('\n--- disassembly ---')
    for idx,(addr,mnem,ops,bts) in enumerate(dis):
        c = COMMENT_MAP.get(mnem,'')
        print(f"[{idx:03}] 0x{addr:x}:\t{mnem}\t{ops}\t; {bts.hex()} {'; '+c if c else ''}")
    if args.no_emulate:
        print('\n-- emulation skipped --'); return
    # prepare emulator
    session = EmulatorSession(code, steps=args.steps, mem_dump=args.mem_dump, allow_syscall=args.allow_syscalls)
    try:
        session.setup()
    except RuntimeError as e:
        print('[safety]', e); sys.exit(1)
    # initial watch
    if args.watch:
        try:
            a,l = args.watch.split(':')
            session.add_watch(int(a,0), int(l,0))
        except Exception as e:
            print('[watch] invalid format, expected addr:len', e)
    breaks = []
    if args.breakpoints:
        breaks = [int(x,0) for x in args.breakpoints.split(',') if x.strip()]
    executed = session.run_to_completion(dis, max_steps=args.steps, interactive=args.interactive, breakpoints=breaks)
    print(f'\n[done] executed {executed} instructions, stop_reason={session.stop_reason}')
    # final registers & flags
    try:
        regs = { 'RAX': session.mu.reg_read(UC_X86_REG_RAX),
                 'RBX': session.mu.reg_read(UC_X86_REG_RBX),
                 'RCX': session.mu.reg_read(UC_X86_REG_RCX),
                 'RDX': session.mu.reg_read(UC_X86_REG_RDX),
                 'RSP': session.mu.reg_read(UC_X86_REG_RSP),
                 'RIP': session.mu.reg_read(UC_X86_REG_RIP),
                 'EFLAGS': session.mu.reg_read(UC_X86_REG_EFLAGS) & 0xffffffff }
        print('\n--- final registers ---')
        for k,v in regs.items():
            if k=='EFLAGS':
                print(f"{k}=0x{v:08x} -> {decode_flags(v)}")
            else:
                print(f"{k}=0x{v:x}")
    except Exception as e:
        print('[final regs] failed', e)
    # memory dumps (data region after code and stack top)
    try:
        code_end = PAGE_ADDR + len(code)
        print(f"\n--- memory dump (data after code) @ 0x{code_end:x} len={args.mem_dump} ---\n")
        print(session.mu.mem_read(code_end, args.mem_dump).hex())
    except Exception as e:
        print('[memdump] failed', e)
    try:
        rsp = session.mu.reg_read(UC_X86_REG_RSP)
        print(f"\n--- stack dump @ 0x{rsp:x} len={args.mem_dump} ---\n")
        print(session.mu.mem_read(rsp, args.mem_dump).hex())
    except Exception as e:
        print('[stackdump] failed', e)
    # save logs if requested
    if args.save_json:
        try:
            with open(args.save_json,'w') as f:
                json.dump(session.log, f, indent=2)
            print('[save] json log written to', args.save_json)
        except Exception as e:
            print('[save] failed', e)
    if args.save_csv:
        try:
            keys = ['idx','addr','mnemonic','op_str','time']
            with open(args.save_csv,'w',newline='') as f:
                w = csv.writer(f)
                w.writerow(keys)
                for r in session.log:
                    w.writerow([r.get(k,'') if k!='addr' else hex(r.get('addr','')) for k in keys])
            print('[save] csv log written to', args.save_csv)
        except Exception as e:
            print('[save csv] failed', e)

if __name__=='__main__':
    main()
