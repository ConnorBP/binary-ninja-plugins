from binaryninja import PluginCommand, TagType

def comment_and_tag_string_xrefs(bv):
    # 1. Setup Tag Type (Bookmark Category)
    tag_name = "String Discovery"
    if tag_name not in bv.tag_types:
        # '🔍' is the icon, 'String Discovery' is the category name
        bv.create_tag_type(tag_name, "🔍")
    
    tag_type = bv.tag_types[tag_name]
    
    count = 0
    bv.begin_undo_actions()
    print(f"[#] Starting String Xref Analysis...")

    for func in bv.functions:
        # Find all strings referenced inside this function
        strings_in_func = []
        for range in func.address_ranges:
            for s in bv.get_strings(range.start, range.end - range.start):
                strings_in_func.append(s.value)
        
        if strings_in_func:
            # Format the string list for the comment
            unique_strings = ", ".join(set(strings_in_func))
            comment_text = f"Target contains strings: {unique_strings}"
            
            # Find callers (Xrefs) to this function
            for xref in bv.get_code_refs(func.start):
                addr = xref.address
                calling_func = xref.function
                
                # Log to Console
                print(f"  [+] Found call at 0x{addr:x} (in {calling_func.name}) -> {unique_strings}")

                # Add Comment
                calling_func.set_comment_at(addr, comment_text)
                
                # Add "Bookmark" (Tag)
                # This makes them appear in the 'Tags' sidebar for easy navigation
                tag = calling_func.create_user_address_tag(addr, tag_type, comment_text)
                
                count += 1

    bv.commit_undo_actions()
    print(f"[#] Finished! Added {count} tags/comments in the '{tag_name}' category.")

PluginCommand.register(
    "String Analysis\\Tag Callers of String Functions",
    "Comments and tags call sites that lead to functions containing strings.",
    comment_and_tag_string_xrefs
)
