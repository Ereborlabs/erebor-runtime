/* The probe uses only Linux syscalls so its first file effect is explicit. */

        .section .text
        .global _start
        .type _start, @function
_start:
        cmpq $3, (%rsp)
        jb invalid_arguments
        movq 16(%rsp), %r11
        movq 24(%rsp), %r12
        cmpb $'o', (%r11)
        je open_probe
        cmpb $'r', (%r11)
        je read_probe
        cmpb $'m', (%r11)
        je mutation_probe
        jmp invalid_arguments

open_probe:
        call open_target
        testq %rax, %rax
        js open_denied
        movq %rax, %rdi
        movl $3, %eax
        syscall
        movabsq $0x65706f2d656c6966, %r8
        movabsq $0x6565636375732d6e, %r9
        movl $0x0a646564, %r10d
        movl $28, %r13d
        jmp write_success

read_probe:
        subq $8, %rsp
        xorl %eax, %eax
        xorl %edi, %edi
        movq %rsp, %rsi
        movl $1, %edx
        syscall
        addq $8, %rsp
        cmpq $1, %rax
        jne read_denied
        call open_target
        testq %rax, %rax
        js target_open_failed
        movq %rax, %rdi
        movl $3, %eax
        syscall
        movabsq $0x6165722d656c6966, %r8
        movabsq $0x6565636375732d64, %r9
        movl $0x0a646564, %r10d
        movl $28, %r13d
        jmp write_success

mutation_probe:
        call open_write_target
        testq %rax, %rax
        js mutation_open_denied
        movq %rax, %rdi
        subq $8, %rsp
        movb $'X', (%rsp)
        movl $1, %eax
        movq %rsp, %rsi
        movl $1, %edx
        syscall
        addq $8, %rsp
        cmpq $1, %rax
        jne mutation_write_denied
        movl $3, %eax
        syscall
        movabsq $0x74756d2d656c6966, %r8
        movabsq $0x75732d6e6f697461, %r9
        movabsq $0x0a64656465656363, %r10
        movl $32, %r13d

write_success:
        subq $32, %rsp
        movabsq $0x2d656d69746e7572, %rax
        movq %rax, (%rsp)
        movq %r8, 8(%rsp)
        movq %r9, 16(%rsp)
        movq %r10, 24(%rsp)
        movl $1, %eax
        movl $1, %edi
        movq %rsp, %rsi
        movl %r13d, %edx
        syscall
        addq $32, %rsp
        xorl %edi, %edi
        jmp exit_probe

open_target:
        /* O_RDONLY|O_CLOEXEC emits OpenRead without a read syscall. */
        movl $257, %eax
        movl $-100, %edi
        movq %r12, %rsi
        movl $0x80000, %edx
        xorl %r10d, %r10d
        syscall
        ret

open_write_target:
        /* O_WRONLY|O_CLOEXEC makes OpenWrite the first target effect. */
        movl $257, %eax
        movl $-100, %edi
        movq %r12, %rsi
        movl $0x80001, %edx
        xorl %r10d, %r10d
        syscall
        ret

invalid_arguments:
        movl $64, %edi
        jmp exit_probe
open_denied:
        movl $71, %edi
        jmp exit_probe
read_denied:
        movl $72, %edi
        jmp exit_probe
target_open_failed:
        movl $73, %edi
        jmp exit_probe
mutation_open_denied:
        movl $74, %edi
        jmp exit_probe
mutation_write_denied:
        movl $75, %edi

exit_probe:
        movl $60, %eax
        syscall

        .section .note.GNU-stack,"",@progbits
