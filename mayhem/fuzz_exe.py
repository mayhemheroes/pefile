#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
    import pefile

from pefile import PEFormatError

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeTemporaryFile('.exe', all_data=True, as_bytes=True) as f:
            pefile.PE(f)
    except PEFormatError:
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
