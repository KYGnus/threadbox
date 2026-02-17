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
    # fallback for newer LIEF versions
    try:
        DLL_CHAR = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
    except AttributeError:
        DLL_CHAR = None  # if not available at all

def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "CFG", " -------------------------------") + colors.DEFAULT))
    
    binary = lief.parse(malware)

    if DLL_CHAR is None:
        print(colors.RED + "[!]" + colors.DEFAULT + " Cannot check CFG: DLL_CHARACTERISTICS not available in this LIEF version")
        csv.write("0,")
        return

    if binary.optional_header.has(DLL_CHAR.GUARD_CF):
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Control Flow Guard (CFG)"))
        csv.write("1,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Control Flow Guard (CFG)"))
        csv.write("0,")

