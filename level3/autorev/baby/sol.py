chall0
import angr
import claripy
def main():
    # Load the binary
    project = angr.Project('rev_spookylicence/spookylicence', auto_load_libs=False)
    # Define symbolic argument (32 bytes)
    arg_len = 0x20
    arg = claripy.BVS('arg', 8 * arg_len)
    # Create symbolic state with argv[1] = symbolic argument
    state = project.factory.full_init_state(
        args=['rev_spookylicence/spookylicence', arg]
    )
    # Restrict argument characters to printable range
    for i in range(arg_len):
        c = arg.get_byte(i)
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)
    # Null-terminate the symbolic string
    #state.solver.add(arg.get_byte(arg_len - 1) == 0)
    # Create simulation manager
    simgr = project.factory.simulation_manager(state)
    # Define the address to find (e.g., success print)
    success_addr = 0x40187d  # Replace with actual success address
    # Start symbolic exploration
    simgr.explore(find=success_addr)
    # If a path was found, print the evaluated argument
    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(arg, cast_to=bytes)
        print('flag:', solution.decode())
    else:
        print('No solution found.')
if _name_ == '_main_':
    main()