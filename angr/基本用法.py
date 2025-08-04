import angr
import claripy

file_path = r'E:\c++的code\issue'

project = angr.Project(file_path)
hook_addr = 0x004011a2

def hook_funct(state):
    state.regs.eax = 0

project.hook(addr=hook_addr, hook=hook_funct, length=2)

init_state = project.factory.entry_state(
    add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES}
)

u = claripy.BVS('u', 8)

init_state.memory.store(0x00404011, u)

def is_good(state):
    return b'you win' in state.posix.dumps(1)
def is_bad(state):
    return b'you lose' in state.posix.dumps(1)

sm = project.factory.simgr(init_state)

sm.explore(find=is_good, avoid=is_bad)

if sm.found:
    found_state = sm.found[0]
    solution = found_state.solver.eval(u)
    print(solution)
    print(bin(solution)[2:].zfill(8))

else:
    print("No solution!")

