from binaryninja import *

import os

symboltype_map = {
        'a': SymbolType.FunctionSymbol,
        'b': SymbolType.DataSymbol,
        'd': SymbolType.DataSymbol,
        'g': SymbolType.DataSymbol,
        't': SymbolType.FunctionSymbol,
        'r': SymbolType.DataSymbol,
        's': SymbolType.DataSymbol,
        'u': SymbolType.ExternalSymbol
}

def loadmap(bv):
    path = get_open_filename_input("Select symbol map", "*.map")

    if not path or not os.path.exists(path):
        show_message_box("Error", "Could not open symbol file", icon=MessageBoxIcon.ErrorIcon)
        return

    lines = open(path, "r").readlines()
    count = 0
    parsing = False

    for line in lines:
        line = line.strip()

        # Start parsing after this header
        if line.startswith("Address") and "Publics by Value" in line:
            parsing = True
            continue

        if not parsing or not line:
            continue

        parts = line.split()

        # MSVC MAP format:
        # 0001:00000000 SymbolName 0000000140001000 f i object.obj
        if len(parts) >= 3:
            try:
                addr = int(parts[2], 16)
                name = parts[1]

                bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
                count += 1
            except:
                continue

    show_message_box("Ok", f"Loaded {count} symbols from file")


typesymbol_map = {
        SymbolType.FunctionSymbol: 't',
        SymbolType.ImportAddressSymbol: 'u',  # May need to fix that later with a proper symbol
        SymbolType.ImportedFunctionSymbol: 'u',
        SymbolType.DataSymbol: 'd', # Binja doesn't care about the specifics so we don't either
        SymbolType.ImportedDataSymbol: 'u',
        SymbolType.ExternalSymbol: 'u'
}

def savemap(bv):
    path = get_save_filename_input("Save symbol map", "*.map", "symbol.map")

    if not path:
        return

    fd = open(path, "w")

    for sym in bv.get_symbols():
        fd.write("{} {} {}\n".format(hex(sym.address)[2:].replace('L', ''), typesymbol_map[sym.type], sym.name))

    fd.close()

