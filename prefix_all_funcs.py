from binaryninja import PluginCommand, interaction

def add_prefix_to_auto_only(bv):
    # Prompt for the prefix
    prefix = interaction.get_text_line_input("Enter prefix for auto-named functions:", "Rename Filtered")
    
    if prefix is None or prefix == "":
        return

    # Handle potential byte-string from UI
    prefix_str = prefix.decode("utf-8") if isinstance(prefix, bytes) else prefix
    count = 0

    # Start an undo group so you can revert all changes with one Ctrl+Z
    bv.begin_undo_actions()
    
    for f in bv.functions:
        # Filter: Only rename functions that haven't been manually named (f.symbol.auto)
        if f.symbol.auto:
            f.name = f"{prefix_str}{f.name}"
            count += 1
            
    bv.commit_undo_actions()
    print(f"Prefix applied to {count} auto-generated functions.")

# Registering with 'PluginCommand.register' puts it in the:
# 1. Top-level 'Plugins' menu
# 2. Right-click context menu
# 3. Command Palette (Ctrl/Cmd + P)
PluginCommand.register(
    "Rename All Functions\\Add Prefix (Auto-Only)", 
    "Adds a prefix only to functions that haven't been manually renamed.", 
    add_prefix_to_auto_only
)
