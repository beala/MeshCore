; LR2021 Patch RAM image header for the MeshCore scanner (scan.c): magic, entry count, entry table.
; Entry 0 runs at ActivatePram.
        .arc_attribute Tag_ARC_ABI_rf16, 1
        .section .text
        .global _start
_start:
        .word   0x600DB002              ; magic
        .word   0x00000003              ; 3 entries
        .word   install                 ; 0
        .word   bg_cmd                  ; 1 (scan.c): background scan
        .word   hello                   ; 2
        .word   0

install:
        mov_s   r0, 2
        j_s     [blink]

; 2: returns 'M' 'C' 'S' '1'
hello:
        ld_s    r3, [r2, 4]
        mov_s   r12, 0x4D
        stb_s   r12, [r3, 0]
        mov_s   r12, 0x43
        stb_s   r12, [r3, 1]
        mov_s   r12, 0x53
        stb_s   r12, [r3, 2]
        mov_s   r12, 0x31
        stb_s   r12, [r3, 3]
        mov_s   r12, 4
        st_s    r12, [r2, 0]
        mov_s   r0, 3
        j_s     [blink]
