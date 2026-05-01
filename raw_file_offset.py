from binaryninja import PluginCommand, interaction


def get_raw_file_offset(bv, addr):
    seg = bv.get_segment_at(addr)
    if not seg:
        interaction.show_message_box(
            "Raw Offset",
            f"Address 0x{addr:x} is not inside a file-backed segment",
        )
        return

    raw = seg.file_offset + (addr - seg.start)

    msg = (
        f"VA:        0x{addr:x}\n"
        f"Segment:   {seg.name or '<unnamed>'}\n"
        f"Raw offset 0x{raw:x}"
    )

    interaction.show_message_box("Raw File Offset", msg)
    interaction.clipboard = hex(raw)

    print(f"[RAW OFFSET] VA 0x{addr:x} -> file offset 0x{raw:x}")


PluginCommand.register_for_address(
    "Get RAW File Offset (IDA-style)",
    "Shows the actual on-disk file offset for this address",
    get_raw_file_offset,
)
