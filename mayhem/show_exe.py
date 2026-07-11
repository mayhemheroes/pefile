#!/usr/bin/env python3
#
# show_exe.py — oracle driver for pefile. Parses the PE file given as argv[1] and prints selected
# header/section values as `key=value` lines that mayhem/test.sh asserts against known answers
# (the SAME pipeline the fuzzer drives: file read -> pefile.PE parse). A neutered/no-op program
# produces no output, so the known-answer assertions fail.
import sys
import pefile


def main():
    pe = pefile.PE(sys.argv[1])
    print("e_magic=0x%04x" % pe.DOS_HEADER.e_magic)
    print("Signature=0x%08x" % pe.NT_HEADERS.Signature)
    print("Machine=0x%04x" % pe.FILE_HEADER.Machine)
    print("NumberOfSections=%d" % pe.FILE_HEADER.NumberOfSections)
    print("Magic=0x%04x" % pe.OPTIONAL_HEADER.Magic)
    print("AddressOfEntryPoint=0x%x" % pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print("ImageBase=0x%x" % pe.OPTIONAL_HEADER.ImageBase)
    print("Subsystem=%d" % pe.OPTIONAL_HEADER.Subsystem)
    print("is_exe=%s" % pe.is_exe())
    print("is_dll=%s" % pe.is_dll())
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        print("Section=%s,VA=0x%x,Raw=0x%x" % (name, s.VirtualAddress, s.SizeOfRawData))


if __name__ == "__main__":
    main()
