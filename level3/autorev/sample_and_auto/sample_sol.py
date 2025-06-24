import angr
import claripy

# --- Configuration ---
BINARY_PATH = "./sample"  # Ensure 'sample' is in the script's directory

# Addresses are absolute, assuming binary base is 0x400000 as in your script
BASE_ADDR = 0x400000    # This doesn't matter if it's 0x400000 or 0x0

MAIN_ADDR = BASE_ADDR + 0x12cf
GETLINE_CALL_ADDR = BASE_ADDR + 0x122a  # Address of the 'call _IO_getline@plt'
# The call instruction (e.g., e8 xx xx xx xx) is 5 bytes long
GETLINE_CALL_LENGTH = 5

# Target address for "Yes" path (call to puts("Yes"))
FIND_ADDR = BASE_ADDR + 0x12f8
# Optional: Avoid address for "No" path (call to puts("No"))
AVOID_ADDR = BASE_ADDR + 0x130e # call puts for "No"

# Memory address for our symbolic input buffer (must be writable)
INPUT_BUFFER_ADDR = 0x605000  # Arbitrary writable address
INPUT_LENGTH = 16

# --- Helper ---
def get_byte(sym_bvs, index):
    """Helper to extract the i-th byte from a BitVector."""
    return sym_bvs.get_byte(index)

# --- Main Script ---
def solve():
    project = angr.Project(
        BINARY_PATH,
        load_options={"main_opts": {"base_addr": BASE_ADDR}},
        auto_load_libs=False
    )

    # Symbolic input string (16 bytes)
    sym_input_str = claripy.BVS("input_str", INPUT_LENGTH * 8)

    # Create a blank state starting at main.
    initial_state = project.factory.blank_state(
        addr=MAIN_ADDR,
        add_options={angr.options.LAZY_SOLVES, angr.options.SYMBOLIC_WRITE_ADDRESSES}
    )

    # Store the symbolic input string in our chosen memory location
    initial_state.memory.store(INPUT_BUFFER_ADDR, sym_input_str)
    print(f"Stored symbolic input at 0x{INPUT_BUFFER_ADDR:x}")

    # Hook _IO_getline@plt
    # The call to _IO_getline@plt is at GETLINE_CALL_ADDR
    @project.hook(GETLINE_CALL_ADDR, length=GETLINE_CALL_LENGTH)
    def hook_getline(state):
        print(f"HOOK: getline at 0x{state.addr:x} triggered.") # state.addr is usually concrete
        # Arguments to getline:
        # rdi (arg0): char **lineptr
        # rsi (arg1): size_t *n
        # rdx (arg2): FILE *stream (e.g., stdin)

        lineptr_ptr_addr = state.regs.rdi  # This is a claripy.BV
        n_ptr_addr = state.regs.rsi        # This is also a claripy.BV

        # 1. Write the address of our symbolic buffer (INPUT_BUFFER_ADDR)
        #    into the location pointed to by lineptr_ptr_addr.
        state.memory.store(lineptr_ptr_addr, INPUT_BUFFER_ADDR, endness=project.arch.memory_endness)
        # Corrected print statement:
        print(f"  HOOK: Set *lineptr (at 0x{state.solver.eval(lineptr_ptr_addr):x}) to 0x{INPUT_BUFFER_ADDR:x}")

        # 2. Write the length of our symbolic buffer (INPUT_LENGTH)
        #    into the location pointed to by n_ptr_addr.
        state.memory.store(n_ptr_addr, claripy.BVV(INPUT_LENGTH, state.arch.bits), endness=project.arch.memory_endness)
        # Corrected print statement:
        print(f"  HOOK: Set *n (at 0x{state.solver.eval(n_ptr_addr):x}) to {INPUT_LENGTH}")

        # 3. getline returns the number of characters read.
        #    Simulate successful read of INPUT_LENGTH characters.
        state.regs.rax = INPUT_LENGTH
        print(f"  HOOK: Set rax (return value) to {INPUT_LENGTH}")

    # Add constraints to the symbolic input string
    for i in range(INPUT_LENGTH):
        byte = get_byte(sym_input_str, i)
        initial_state.solver.add(byte != 0)  # Non-null constraint
        # Printable ASCII constraints significantly reduce search space.
        # Comment these out if no solution is found and non-printable input is acceptable.
        initial_state.solver.add(byte >= 0x20)
        initial_state.solver.add(byte <= 0x7e)
    print(f"Applied constraints to {INPUT_LENGTH} input bytes (non-null, printable ASCII).")

    # Create simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    print(f"\nExploring paths from main (0x{MAIN_ADDR:x})...")
    print(f"Targeting 'Yes' at 0x{FIND_ADDR:x}, avoiding 'No' at {f'0x{AVOID_ADDR:x}' if AVOID_ADDR is not None else 'None'}") # Corrected line
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR if AVOID_ADDR else None)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(sym_input_str, cast_to=bytes)
        print(f"\n!!! Solution Found !!!")
        print(f"Input (bytes): {solution}")
        try:
            # Attempt to decode as ASCII, replace errors for display
            print(f"Input (string): {solution.decode('ascii', errors='replace')}")
        except Exception as e:
            print(f"Input (hex): {solution.hex()} (Error decoding as string: {e})")

        print("\nIndividual byte values (hex and char):")
        for i in range(INPUT_LENGTH):
            byte_val = found_state.solver.eval(get_byte(sym_input_str, i))
            char_repr = chr(byte_val) if 0x20 <= byte_val <= 0x7e else '.'
            print(f"Byte {i:2}: {hex(byte_val):<5} ('{char_repr}')")
    else:
        print("\nNo solution found.")
        if simgr.errored:
            print("Errored states encountered:")
            for i, error_record in enumerate(simgr.errored):
                print(f"  Error {i+1}: {error_record.error} at 0x{error_record.state.addr:x}")
                # print(f"    Traceback: {error_record.traceback}") # Can be very verbose
        if simgr.deadended:
             print(f"Number of deadended states: {len(simgr.deadended)}")
        # You can inspect simgr.deadended states to see why they stopped.

    return simgr # For further inspection in an interactive session if needed

if __name__ == "__main__":
    solve()