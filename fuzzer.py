import angr, monkeyhex
import random, time
import sys, os, subprocess
from collections import deque


def readConfig(config_file):
    with open(config_file, "r") as f:
        binary_name = f.readline().strip()
        cmd_nargs = int(f.readline().strip())
        cmd_arglens = list(map(int, f.readline().strip().split()))
        std_len = int(f.readline().strip())
        max_branches = int(f.readline().strip())
        time_limit = int(f.readline().strip())

    return binary_name, cmd_nargs, cmd_arglens, std_len, max_branches, time_limit


def genSymbolicCommandLineArgs(_state, cmd_nargs, cmd_arglens):
    if len(cmd_arglens) < cmd_nargs:
        cmd_arglens += [cmd_arglens[-1]] * (cmd_nargs - len(cmd_arglens))
    # print(cmd_arglens)

    return [
        _state.solver.BVS("inx{0}".format(i), max(leni, 1) * 8)
        for (i, leni) in enumerate(cmd_arglens)
    ]


def getSymbolicStdin(_state, size):
    return _state.solver.BVS("stdin", max(size, 1) * 8)


def addSpecifigConstraints(state, cmd_inxs, std_inx):
    for cmd_inx in cmd_inxs:
        state.add_constraints(cmd_inx[-1:-8] != 0)


def genInitState(proj, cmd_inxs, std_inx, cmd_ins, std_in):
    stdin_file = angr.storage.file.SimFile("/dev/stdin", "r", size=len(std_inx) / 8)
    state = proj.factory.entry_state(
        fs={"/dev/stdin": stdin_file}, args=[""] + cmd_inxs
    )
    state.posix.files[0].content.store(0, std_inx)
    if std_in:
        state.add_constraints(std_inx == std_in)

    assert len(cmd_inxs) >= len(cmd_ins)
    for i in range(len(cmd_ins)):
        state.add_constraints(cmd_inxs[i] == cmd_ins[i])

    addSpecifigConstraints(state, cmd_inxs, std_inx)

    return state


def executeState(
    proj, state, max_branches
):  # will only randomly pick one path if multiple paths possible
    simgr = proj.factory.simulation_manager(state)
    branches = 0
    while simgr.active and branches < max_branches:
        simgr.step(
            until=lambda s: not s.active or s.active[0].history.recent_constraints
        )
        branches += 1
        if len(simgr.active) == 2:
            r = random.randint(0, 1)
            simgr.active.pop(r)

    if simgr.active:
        return simgr.active[0]
    elif simgr.deadended:
        return simgr.deadended[0]
    elif simgr.errored:
        return simgr.errored[0].state
    else:
        return None


def getConstraints(proj, start, end):
    conds_ini = start.history.constraints_since(start)
    constraints = end.history.constraints_since(start)

    for _ in range(len(conds_ini)):  # pop constraints for input
        constraints.pop()
    constraints.reverse()  # adjust to correct order

    return [
        c.ast for c in constraints
    ]  # extract ast/condition from Simulation Action Object


def executeSymbolic(proj, cmd_inxs, std_inx, cmd_ins, std_in, max_branches):
    start = genInitState(proj, cmd_inxs, std_inx, cmd_ins, std_in)
    end = executeState(proj, start, max_branches)
    assert end != None and "unhandled case"

    return getConstraints(proj, start, end)


def getInversedConds(proj, conds, i):
    state = proj.factory.blank_state()
    new_conds = conds[:i]
    new_conds.append(state.solver.Not(conds[i]))
    return new_conds


def solveForInput(proj, cmd_inxs, std_inx, conds):
    state = proj.factory.blank_state()
    addSpecifigConstraints(state, cmd_inxs, std_inx)
    state.add_constraints(*conds)

    cmd_ins = (
        [state.solver.eval(cmd_inx, cast_to=str) for cmd_inx in cmd_inxs]
        if state.satisfiable()
        else None
    )
    std_in = state.solver.eval(std_inx, cast_to=str) if state.satisfiable() else None

    return cmd_ins, std_in


def testBinaryWithInput(binary_path, temp_file, cmd_ins, std_in):
    cmd_args = [cmd_in.strip("\x00") for cmd_in in cmd_ins]
    # cmd_args = cmd_ins
    # std_input = std_in.replace('\x00', ' ').strip()
    std_input = std_in

    with open(temp_file, "w") as f:
        f.write(std_input)

    f_stdin = open(temp_file, "r")
    f_stdout = open("/dev/null", "w")

    command = [binary_path] + cmd_args
    return_code = subprocess.call(
        command, stdin=f_stdin, stdout=f_stdout, stderr=f_stdout
    )
    # command = [binary_path] + cmd_args + ['<', temp_file, '> /dev/null']
    # command = ' '.join(command)
    # print("command: {0}".format(command))
    f_stdin.close()
    f_stdout.close()

    os.remove(temp_file)

    return command, return_code


def fuzz(proj, binary_path, temp_file, cmd_inxs, std_inx, max_branches, time_limit):
    start = time.time()

    # initial inputs
    conds_ini = executeSymbolic(proj, cmd_inxs, std_inx, [], None, max_branches)
    cmd_ins_ini, std_in_ini = solveForInput(proj, cmd_inxs, std_inx, conds_ini)

    # Start trying all paths
    cmd_ins_batch = []
    std_in_batch = []
    comamnd_batch = []
    return_code_batch = []

    queue = deque([])
    queue.append((cmd_ins_ini, std_in_ini, -1))

    total_paths = 0

    while queue:
        if (time.time() - start) > time_limit:
            print("reaches time limit, stopping...")
            break

        if not queue:
            break

        cmd_ins, std_in, bound = queue.popleft()
        # TODO: run actual program and check bugs
        command, return_code = testBinaryWithInput(
            binary_path, temp_file, cmd_ins, std_in
        )
        if return_code != 0:
            cmd_ins_batch.append(cmd_ins)
            std_in_batch.append(std_in)
            comamnd_batch.append(command)
            return_code_batch.append(return_code)

            # print(cmd_ins)
            # print([std_in])
            # print(command)
            # print(return_code)
            # print

        _start = time.time()
        conds = executeSymbolic(proj, cmd_inxs, std_inx, cmd_ins, std_in, max_branches)
        # print('executeSymbolic, time: {0}'.format(time.time() - _start))
        # print("\n")

        for i in range(bound + 1, len(conds)):
            conds_new = getInversedConds(proj, conds, i)
            cmd_ins_new, std_in_new = solveForInput(proj, cmd_inxs, std_inx, conds_new)
            if cmd_ins_new != None:
                queue.append((cmd_ins_new, std_in_new, i))

        total_paths += 1

    return (
        cmd_ins_batch,
        std_in_batch,
        return_code_batch,
        total_paths,
        time.time() - start,
    )


def main(config_file, output_file, temp_file):
    print(
        (
            "config file: {0}, output file: {1}, temp file: {2}".format(
                config_file, output_file, temp_file
            )
        )
    )

    binary_name, cmd_nargs, cmd_arglens, std_len, max_branches, time_limit = readConfig(
        config_file
    )
    binary_path = os.path.join(os.path.dirname(config_file), binary_name)

    print(
        (
            "binary: {0}, cmd_nargs: {1}, cmd_arglens: {2}, std_len: {3}, branches: {4}, time: {5}".format(
                binary_path, cmd_nargs, cmd_arglens, std_len, max_branches, time_limit
            )
        )
    )

    proj = angr.Project(binary_path, auto_load_libs=False)
    _state = proj.factory.entry_state()

    cmd_inxs = genSymbolicCommandLineArgs(_state, cmd_nargs, cmd_arglens)
    std_inx = getSymbolicStdin(_state, std_len)

    cmd_ins_batch, std_in_batch, return_code_batch, total_paths, time_collapsed = fuzz(
        proj, binary_path, temp_file, cmd_inxs, std_inx, max_branches, time_limit
    )

    with open(output_file, "w") as f:
        # import json
        for cmd_ins, std_in, return_code in zip(
            cmd_ins_batch, std_in_batch, return_code_batch
        ):
            cmd_ins = [_in.strip("\x00") for _in in cmd_ins]
            std_in = [std_in]
            # json.dump([return_code, cmd_ins], f)
            f.write(str([return_code, cmd_ins, std_in]) + "\n")

    """
  print('-- possible inputs --')
  for cmd_ins, std_in, return_code in zip(cmd_ins_batch, std_in_batch, return_code):
    print(cmd_ins)
    print(std_in)
    print(return_code)
  print('---------------------')
  """
    print(("{0} failing test cases found.".format(len(return_code_batch))))
    print(("{0} different paths covered.".format(total_paths)))
    print(("time collapsed: {0}".format(time_collapsed)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(("Usage: python {0} <config_file> <output_file>".format(sys.argv[0])))
        exit(1)
    else:
        config_file = sys.argv[1]
        output_file = sys.argv[2]
        temp_file = ".fz_temp"
        main(config_file, output_file, temp_file)
