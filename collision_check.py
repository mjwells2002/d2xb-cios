# SPDX-License-Identifier: LGPL-2.1-only
# Copyright Andrew Piroli 2022
import re
import sys
import dataclasses
from typing import Dict, Iterable, List, Tuple, Union


@dataclasses.dataclass(frozen=True, order=True)
class Section:
    startaddr: int
    size: int
    tag: str = dataclasses.field(default="Unknown!")


@dataclasses.dataclass(frozen=True, order=True)
class DotApp:
    filename: str
    sections: List[Section] = dataclasses.field(default_factory=list)


# Regex for capturing find output with the filename
# Example input:
# "File: ./relative/path/to/a/file"
# Output Group 1 is "./relative/path/to/a/file"
start_of_record = re.compile(r"File: (.*)")

# Regex to parse the LOAD header from readelf
# Does not capture the flags or alignment since we only after memory addresses.
# Example input:
# "  LOAD           0x111111 0x22222222 0x12345678 0x9ABCD 0xEF012 R E 0x4"
# Output:
# Group 1: Offset "0x111111"
# Group 2: VirtAddr "0x22222222"
# Group 3: PhysAddr "0x12345678"
# Group 4: FileSiz "0x9ABCD"
# Group 5: MemSiz "0xEF012"
load_header = re.compile(
    r"\s?LOAD\s*(0x[0-9|a-f]{5,8})\s(0x[0-9|a-f]{5,8})\s(0x[0-9|a-f]{5,8})\s(0x[0-9|a-f]{5,8})\s(0x[0-9|a-f]{5,8})",
    re.IGNORECASE,
)

# Returns the parameters so they can be useful in list comprehensions
def overlaps(a: Section, b: Section) -> Tuple[bool, Section, Section]:
    return (
        a.startaddr in range(b.startaddr, b.startaddr + b.size)
        or b.startaddr in range(a.startaddr, a.startaddr + a.size),
        a,
        b,
    )


# a version of builtin any() customized to take a tuple from overlaps()
# It also returns the first overlap instead of just a bool
def any_return(a: Iterable[Tuple[bool, Section, Section]]) -> Union[Section, bool]:
    for item in a:
        if item[0]:
            return item[1]
    return False


# This is where the fun begins
processed_readelf_output: Dict[str, DotApp] = dict()
in_file: Union[None, str] = None

# Expects output from `find ... -exec readelf -l ...` on stdin
for readelf_line in sys.stdin:
    # find tells us the filename, before running the exec
    # keep track of that so we know what readelf output is in each file
    if match := start_of_record.search(readelf_line):
        in_file = match.group(1)
        processed_readelf_output.update({in_file: DotApp(in_file)})
        continue
    elif (
        in_file
    ):  # We know what file we are in and are going to read some output from readelf
        # Check if it's output we are interested in
        if match := load_header.search(readelf_line):
            # We are only dealing with physical addresses
            physaddr = int(match.group(3), 16)
            memsiz = int(match.group(5), 16)
            if (
                physaddr == 0
            ):  # Can safely ignore this since they all have a load at 0x0
                continue
            # Store them for later processing
            processed_readelf_output[in_file].sections.append(
                Section(physaddr, memsiz, in_file)
            )
    else:
        # Any other output, we don't care about
        pass

found = False
all_sections: List[Section] = list()

# Loop over everything we got
# The keys were just filenames for easy access in the stdin parsing phase
# We don't need them anymore since there's an extra copy of that stashed in Section() dataclass
for app in processed_readelf_output.values():
    # loop over all sections belonging to a file
    for section in app.sections:
        # check if any of those sections overlap with any section in the all_sections list
        # if so, assign it to first_overlap so it can be printed to the screen
        # Yes this is a triple nested for loop inside any_return(), I don't care - it works (probably)
        if first_overlap := any_return(
            [overlaps(previous_sections, section) for previous_sections in all_sections]
        ):
            print(
                f"Collision detected! File: {app.filename} Section: {section} Overlapped with {first_overlap}"
            )
            found = True
        all_sections.append(section)
if not found:
    print("No collisions detected! PogYou")
