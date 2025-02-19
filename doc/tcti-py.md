# Python TCTI (py-tcti)

The Python TCTI can be used to write TCTI modules in Python3. This allows a user to make use of the
robust language features and modules that are available in Python3.

## Invoking the Python TCTI

Like implementing any TCTI, one can follow the friendly conventions or provide the full path of the shared
object to `Tss2_TCTILdr_Initialize` or one can instantiate the TCTI directly with `TSS2_TCTI_Py_Initialize`.

One needs to specify a module name (the name of a python file) and optionally arguments to pass to an init
function in that module. The signature of this method is: `def tcti_init(args: str) -> Object` and the
args string passed in is the args option appended on the configuration string.

One possible way to use it with the command line tools is via the `--tcti=py:<modname>:<args>`. For
example:
```bash
# Python3 file pytcti.py exists in $HOME
PYTHONPATH=$HOME tpm2_getcap --tcti=py:pytcti properties-fixed
```

## Example Python TCTI

The below sample code TCTI just uses tpm2-pytss package to call TCTILdr with whatever
argument string is provided. It just showcases full path delivery of commands. To invoke
the example code below, assuming that the python file is named pytcti.py and you want
to connect to tpm2-abrmd resource manager do:
```bash
PYTHONPATH=$HOME tpm2_getcap --tcti=py:pytcti:tabrmd properties-fixed
```

```python3
# SPDX-License-Identifier: BSD-2-Clause
from tpm2_pytss import TCTILdr


class MyPyTCTI(object):
    def __init__(self, args: str):
        c = args.split(":", maxsplit=1)
        mod = c[0]
        args = c[1] if len(c) > 1 else "None"
        print(f"PYTHON: Initializing TCTI Ldr with mod: {mod} args: {args}")
        self._tcti = TCTILdr(mod, args)

    @property
    def magic(self):
        # Optional Method
        print("PYTHON magic")
        return 42

    def receive(self, timeout: int) -> bytes:
        print("PYTHON receive")
        return self._tcti.receive(timeout=timeout)

    def transmit(self, data: bytes):
        print("PYTHON transmit")
        self._tcti.transmit(data)


def tcti_init(args: str) -> MyPyTCTI:
    print(f"PYTHON tcti_init called with: {args}")
    return MyPyTCTI(args)
```
