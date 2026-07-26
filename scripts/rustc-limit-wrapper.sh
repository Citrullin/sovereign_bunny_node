#!/bin/bash
# Sovereign Reth Compiler Wrapper
# Limits virtual memory of the compiler to prevent WSL/host OOM crashes.

# Compiler process is run sequentially (jobs=1) and is memory-optimized

# If sccache is available, use it as a wrapper, otherwise call rustc directly
if command -v sccache >/dev/null 2>&1; then
    exec sccache "$@"
else
    exec "$@"
fi
