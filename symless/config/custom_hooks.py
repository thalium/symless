from typing import Dict, Tuple

call_hooks: Dict[Tuple[int, str], Dict[str, str]]
call_hooks = {}


# Not documented until now because WIP
call_hooks = {
    (0x4C90, "sign_pointer"): {"rax": "rdi"},
    (0x4D20, "auth_pointer"): {"rax": "rdi"},
}
