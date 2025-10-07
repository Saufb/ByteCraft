; ByteCraft.asm - advanced educational x86_64 example (nested loops, buffer ops, call/ret)
; Written to be safe for emulation: NO syscalls.

BITS 64

section .data
arr: dq 1,2,3,4,5,6,7,8
n: dq 8
sum: dq 0
msg: db "ByteCraft v2",0

section .bss
buf: resb 64

section .text
global _start

_start:
    ; initialize pointers
    lea rsi, [rel arr]
    mov rcx, [rel n]        ; outer count = 8
    xor rax, rax            ; sum = 0
    xor rdx, rdx            ; inner counter

outer_loop:
    cmp rcx, 0
    je outer_done
    ; inner loop: add first rcx elements to sum
    mov rdx, rcx
    xor rbx, rbx            ; index = 0
inner_loop:
    cmp rbx, rdx
    jge inner_done
    mov r8, [rsi + rbx*8]
    add rax, r8
    inc rbx
    jmp inner_loop
inner_done:
    sub rcx, 1
    jmp outer_loop
outer_done:
    ; store sum
    mov [rel sum], rax

    ; buffer ops (safe)
    lea rdi, [rel buf]
    mov r9, 0x41
    mov rcx, 16
buf_fill:
    mov byte [rdi + r9 - 0x40], 0x41
    inc r9
    dec rcx
    jnz buf_fill

    ; call helper
    call compute_extra
    ; final tweak
    add rax, 7

    ; finish sequence (no syscall; ret to end)
    nop
    nop
    ret

compute_extra:
    ; simple function: read sum and add 3
    mov rax, [rel sum]
    add rax, 3
    ret
