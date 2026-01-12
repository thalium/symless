import idaapi


def is_arch_supported() -> bool:
    return is_proc_supported()


def is_proc_supported() -> bool:
    # name = idaapi.inf_get_procname()
    return True  # every arch should be supported by microcode


def get_proc_name() -> str:
    return idaapi.inf_get_procname()
