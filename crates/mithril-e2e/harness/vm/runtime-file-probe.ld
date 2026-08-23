ENTRY(_start)

/* One X-only segment lets each mode reach its first file operation. */
PHDRS
{
  probe PT_LOAD FILEHDR PHDRS FLAGS(1);
}

SECTIONS
{
  . = 0x400000 + SIZEOF_HEADERS;
  .text : { *(.text) *(.rodata) } :probe
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
