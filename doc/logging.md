# Compile time log levels

At compile time the maximum log level can be specified. This allows distros to
disable the overhead code and reduce overall code size.

# Runtime log level

At runtime, the log level is determined by an environment variable. The default
log level is WARNING. The level can be changed by setting the TSS2_LOG
environment variable.

Possible levels are: NONE, ERROR, WARNING, INFO, DEBUG, TRACE

The level can be set for all module using the `all` module name or individually
per module. The environment variable is evaluated left to right.

Example: `TSS2_LOG=all+ERROR,marshal+TRACE,tcti+DEBUG

# Implementation

Each source code file specifies its corresponding module before including log.h.
```
#define LOGMODULE tcti
#include "log.h"
```
Optionally, the default log-level for this module can be set:
```
#define LOGMODULE tcti
#define LOGDEFAULT ERROR
#include "log.h"
```

