import angr
import claripy
import subprocess
import os

# --- angr Solver Configuration (from your script) ---
# Addresses are offsets from BASE_ADDR
MAIN_ADDR_OFFSET = 0x12cf
GETLINE_CALL_ADDR_OFFSET = 0x122a
GETLINE_CALL_LENGTH = 5
FIND_ADDR_OFFSET = 0x12f8
AVOID_ADDR_OFFSET = 0x130e

INPUT_BUFFER_ADDR = 0x605000  # Arbitrary writable address
INPUT_LENGTH = 16

# --- Batch Processing Configuration ---
BASE_ADDR = 0x400000  # Assuming this is constant for all PIE binaries
BINARY_PATH_TEMPLATE = "./challenge_{}" # Path to your challenge binaries
NUMBER_OF_CHALLENGES = 100 # From 0 to 99

# --- Helper ---
def get_byte(sym_bvs, index):
    return sym_bvs.get_byte(index)

# --- angr Solver Function (adapted from your script) ---
def solve_with_angr(binary_path, challenge_index):
    print(f"\n--- Solving for {binary_path} ---")
    project = angr.Project(
        binary_path,
        load_options={"main_opts": {"base_addr": BASE_ADDR}},
        auto_load_libs=False
    )

    sym_input_str = claripy.BVS(f"input_str_{challenge_index}", INPUT_LENGTH * 8)

    # Calculate absolute addresses for this binary
    main_addr = BASE_ADDR + MAIN_ADDR_OFFSET
    getline_call_addr = BASE_ADDR + GETLINE_CALL_ADDR_OFFSET
    find_addr = BASE_ADDR + FIND_ADDR_OFFSET
    avoid_addr = BASE_ADDR + AVOID_ADDR_OFFSET

    initial_state = project.factory.blank_state(
        addr=main_addr,
        add_options={angr.options.LAZY_SOLVES, angr.options.SYMBOLIC_WRITE_ADDRESSES}
    )

    initial_state.memory.store(INPUT_BUFFER_ADDR, sym_input_str)

    @project.hook(getline_call_addr, length=GETLINE_CALL_LENGTH)
    def hook_getline(state):
        # print(f"HOOK: getline at 0x{state.addr:x} for {binary_path}")
        lineptr_ptr_addr = state.regs.rdi
        n_ptr_addr = state.regs.rsi
        state.memory.store(lineptr_ptr_addr, INPUT_BUFFER_ADDR, endness=project.arch.memory_endness)
        # print(f"  HOOK: Set *lineptr (at 0x{state.solver.eval(lineptr_ptr_addr):x}) to 0x{INPUT_BUFFER_ADDR:x}")
        state.memory.store(n_ptr_addr, claripy.BVV(INPUT_LENGTH, state.arch.bits), endness=project.arch.memory_endness)
        # print(f"  HOOK: Set *n (at 0x{state.solver.eval(n_ptr_addr):x}) to {INPUT_LENGTH}")
        state.regs.rax = INPUT_LENGTH

    for i in range(INPUT_LENGTH):
        byte = get_byte(sym_input_str, i)
        initial_state.solver.add(byte != 0)
        initial_state.solver.add(byte >= 0x20)
        initial_state.solver.add(byte <= 0x7e)

    simgr = project.factory.simulation_manager(initial_state)
    # print(f"Exploring paths for {binary_path} from main (0x{main_addr:x})...")
    # print(f"Targeting 'Yes' at 0x{find_addr:x}, avoiding 'No' at {f'0x{avoid_addr:x}' if avoid_addr is not None else 'None'}")
    
    try:
        simgr.explore(find=find_addr, avoid=avoid_addr if avoid_addr is not None else None)
    except Exception as e:
        print(f"  angr exploration error for {binary_path}: {e}")
        return None


    if simgr.found:
        found_state = simgr.found[0]
        solution_bytes = found_state.solver.eval(sym_input_str, cast_to=bytes)
        print(f"  angr: Solution found for {binary_path}!")
        return solution_bytes
    else:
        print(f"  angr: No solution found for {binary_path}.")
        if simgr.errored:
            for i, error_record in enumerate(simgr.errored):
                print(f"    Error {i+1}: {error_record.error} at 0x{error_record.state.addr:x}")
        return None

# --- Main Batch Processing Script ---
def main():
    all_results = {} # To store results: { "challenge_0": {"angr_solution": "...", "verified": True/False/Error}, ... }

    for i in range(NUMBER_OF_CHALLENGES):
        binary_name = BINARY_PATH_TEMPLATE.format(i)
        all_results[binary_name] = {"angr_solution_str": None, "verified_output": None, "verification_status": "Not Run"}

        if not os.path.exists(binary_name):
            print(f"Binary {binary_name} not found. Skipping.")
            all_results[binary_name]["verification_status"] = "Binary Not Found"
            continue
        
        if not os.access(binary_name, os.X_OK):
            print(f"Binary {binary_name} is not executable. Skipping. (Hint: chmod +x {binary_name})")
            all_results[binary_name]["verification_status"] = "Not Executable"
            continue

        # 1. Solve with angr
        solution_bytes = solve_with_angr(binary_name, i)

        if solution_bytes:
            try:
                solution_str = solution_bytes.decode('ascii')
                all_results[binary_name]["angr_solution_str"] = solution_str
                print(f"  angr: Decoded solution for {binary_name}: '{solution_str}'")

                # 2. Verify by running the binary with the solution
                print(f"  Verifying {binary_name} with input: '{solution_str}'")
                try:
                    # Add a newline as if user pressed Enter, common for getline
                    process_input = (solution_str + "\n").encode('ascii')
                    
                    result = subprocess.run(
                        [binary_name],
                        input=process_input,
                        capture_output=True,
                        text=False, # Capture as bytes
                        timeout=5 # Timeout for safety
                    )
                    
                    stdout_bytes = result.stdout
                    stderr_bytes = result.stderr
                    
                    # Decode stdout and stderr, replacing errors
                    stdout_str = stdout_bytes.decode('ascii', errors='replace').strip()
                    stderr_str = stderr_bytes.decode('ascii', errors='replace').strip()

                    all_results[binary_name]["verified_output"] = stdout_str
                    print(f"    {binary_name} STDOUT: '{stdout_str}'")
                    if stderr_str:
                        print(f"    {binary_name} STDERR: '{stderr_str}'")

                    if "Yes" in stdout_str:
                        print(f"    SUCCESS: {binary_name} printed 'Yes'!")
                        all_results[binary_name]["verification_status"] = "Verified - Yes"
                    else:
                        print(f"    FAILURE: {binary_name} did NOT print 'Yes'. Output: '{stdout_str}'")
                        all_results[binary_name]["verification_status"] = "Verified - No 'Yes'"
                
                except subprocess.TimeoutExpired:
                    print(f"    ERROR: Timeout expired while running {binary_name}.")
                    all_results[binary_name]["verification_status"] = "Verification Timeout"
                except Exception as e:
                    print(f"    ERROR: Exception during verification of {binary_name}: {e}")
                    all_results[binary_name]["verification_status"] = f"Verification Exception: {e}"

            except UnicodeDecodeError:
                all_results[binary_name]["angr_solution_str"] = solution_bytes.hex() # Store as hex if not ASCII
                print(f"  angr: Solution for {binary_name} is not valid ASCII. Hex: {solution_bytes.hex()}")
                all_results[binary_name]["verification_status"] = "Angr Solution Not ASCII"
        else:
            all_results[binary_name]["verification_status"] = "Angr No Solution"

    # Print summary
    print("\n\n--- Batch Summary ---")
    for binary, data in all_results.items():
        print(f"{binary}:")
        print(f"  Angr Solution: {data['angr_solution_str']}")
        print(f"  Verification Status: {data['verification_status']}")
        if data['verified_output'] is not None:
             print(f"  Actual Output: '{data['verified_output']}'")
        print("-" * 20)

if __name__ == "__main__":
    main()