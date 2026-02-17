import lief
from . import colors

# Set logging level
if hasattr(lief.logging, "LEVEL"):
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
elif hasattr(lief.logging, "Level"):
    lief.logging.set_level(lief.logging.Level.ERROR)
else:
    lief.logging.disable()

# Compatibility for DLL_CHARACTERISTICS
try:
    DLL_CHAR = lief.PE.DLL_CHARACTERISTICS
except AttributeError:
    try:
        DLL_CHAR = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
    except AttributeError:
        DLL_CHAR = None  # not available

# check if PE file uses Structured Exception Handling (SEH)
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "SEH", " -------------------------------") + colors.DEFAULT))
    
    binary = lief.parse(malware)

    if DLL_CHAR is None:
        print(colors.RED + "[!]" + colors.DEFAULT + " Cannot check SEH: DLL_CHARACTERISTICS not available in this LIEF version")
        csv.write("0,")
        return

    if binary.optional_header.has(DLL_CHAR.NO_SEH):
        print((colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Structured Exception Handling (SEH)"))
        csv.write("0,")
    else:
        print((colors.GREEN + "[" + '\u2713' + "]" + colors.DEFAULT + " The file supports Structured Exception Handling (SEH)"))
        csv.write("1,")
