import pickle
import time

import idaapi
import idc

import symless.conflict as conflict
import symless.cpustate.arch as arch
import symless.generation as generation
import symless.model as model
import symless.symbols as symbols
import symless.utils.utils as utils


def start_analysis(config_path):
    # check binary type
    if not arch.is_arch_supported():
        utils.logger.error("Unsupported arch (%s) or filetype" % arch.get_proc_name())
        idc.qexit(0)

    # initial ida autoanalysis
    start = time.time()
    idaapi.auto_wait()
    utils.print_delay("Info: initial IDA autoanalysis", start, time.time())

    # generate model
    start = time.time()
    model_context = model.generate_model(config_path)
    utils.print_delay("Info: model generation done", start, time.time())

    if model_context is not None:

        # solve conflicts in the model
        start = time.time()
        conflict.solve_conflicts(model_context)
        utils.print_delay("Info: conflicts solved", start, time.time())

        # get info from potential symbols
        symbols.name_structures(model_context)

        # import data in ida
        start = time.time()

        generation.make_symless_dir()

        total = generation.generate_structs(model_context)
        utils.print_delay("Info: ida database updated", start, time.time())

        # finalize operations
        start = time.time()
        idaapi.auto_wait()
        utils.print_delay("Info: final IDA autoanalysis", start, time.time())

        utils.logger.info("%d structures generated" % total)

        with open(f"{idaapi.get_input_file_path()}_model.pickle", "wb") as f:
            pickle.dump(model_context, f)