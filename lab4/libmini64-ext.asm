section .text
    global time
    global srand
    global rand
    global grand
    global sigaddset
    global sigdelset
    global sigismember
    global sigfillset
    global sigemptyset
    global sigprocmask
    global setjmp
    global sigsetjmp
    global longjmp
    global siglongjmp

extern sigset_t

time:
    ; rdi is ignored (parameter to time()), so no need to handle it
    mov     eax, 201         ; syscall number for time (man syscall)
    xor     edi, edi         ; argument is NULL (ignored)
    syscall                  ; invoke the syscall
    ret

srand:
    mov     rax, rdi        ; rdi = unsigned s (1st argument)
    sub     rax, 1          ; rax = s - 1
    mov     [rel seed], rax ; seed = s - 1
    ret

rand:
    ; Load seed into rax
    mov     rax, [rel seed]

    ; Multiply rax by constant (lower 64-bit multiply)
    mov     rbx, 6364136223846793005
    mul     rbx                ; rdx:rax = rax * rbx (unsigned)

    ; Add 1 to result (in rax)
    add     rax, 1

    ; Store new seed
    mov     [rel seed], rax

    ; Shift right by 33 and return
    shr     rax, 33
    ret
grand:
    mov rax, [rel seed]
    ret

; int sigaddset(sigset_t *set, int signum)
sigaddset:
    cmp esi, 1
    jl .err                 ; invalid signal
    cmp esi, 32
    jg .err
    mov ecx, esi
    dec ecx                 ; shift by (signum - 1)
    mov rax, 1
    shl rax, cl             ; rax = (1ULL << (signum - 1))
    or [rdi], rax           ; set->mask.l[0] |= rax
    xor eax, eax
    ret
.err:
    mov eax, -1
    ret

; int sigdelset(sigset_t *set, int signum)
sigdelset:
    cmp esi, 1
    jl .err
    cmp esi, 32
    jg .err
    mov ecx, esi
    dec ecx
    mov rax, 1
    shl rax, cl
    not rax
    and [rdi], rax          ; set->mask.l[0] &= ~bit
    xor eax, eax
    ret
.err:
    mov eax, -1
    ret

; int sigismember(const sigset_t *set, int signum)
sigismember:
    cmp esi, 1
    jl .err
    cmp esi, 32
    jg .err
    mov ecx, esi
    dec ecx
    mov rax, 1
    shl rax, cl
    mov rdx, [rdi]
    test rdx, rax
    jne .yes
    xor eax, eax            ; return 0
    ret
.yes:
    mov eax, 1              ; return 1
    ret
.err:
    mov eax, -1
    ret

sigfillset:
    mov qword [rdi], -1     ; set->mask.l[0] = 0xFFFFFFFFFFFFFFFF
    xor eax, eax            ; return 0
    ret

sigemptyset:
    mov qword [rdi], 0      ; set->mask.l[0] = 0
    xor eax, eax            ; return 0
    ret

; test5 -------------------------
sigprocmask:
    ; rdi is ignored (parameter to time()), so no need to handle it
    mov     r10, 8
    mov     eax, 14         ; syscall number for time (man syscall)
    syscall                  ; invoke the syscall
    ret
; test6 ---------------------------------
; int setjmp(jmp_buf env)
setjmp:
sigsetjmp:
    ; rdi = env (pointer to jmp_buf)

    mov [rdi + 0*8], rbx
    mov [rdi + 1*8], rbp
    mov rax, rsp
    mov [rdi + 2*8], rax
    mov [rdi + 3*8], r12
    mov [rdi + 4*8], r13
    mov [rdi + 5*8], r14
    mov [rdi + 6*8], r15
    mov rax, [rsp]                ; return address
    mov [rdi + 7*8], rax

    lea rdx, [rdi + 8*8]         ; rdx = &env->mask
    xor rdi, rdi                 ; how = SIG_BLOCK (0)
    xor rsi, rsi                 ; set = NULL
    mov r10, 8
    call sigprocmask

    xor eax, eax
    ret
; test7------------------------------

longjmp:
siglongjmp:
    ; rdi = env (jmp_buf), rsi = val
    ; Restore signal mask from env->mask
    push rsi
    push rdi
    lea rsi, [rdi + 8*8]     ; rsi = set
    mov rdi, 2             ; how = 
    xor rdx, rdx             ; oldset = NULL
    mov r10, 8
    call sigprocmask
    pop rdi
    pop rsi

    mov rbx, [rdi + 0*8]
    mov rbp, [rdi + 1*8]
    mov rsp, [rdi + 2*8]
    mov r12, [rdi + 3*8]
    mov r13, [rdi + 4*8]
    mov r14, [rdi + 5*8]
    mov r15, [rdi + 6*8]

    ; Ensure non-zero return value
    mov rax, rsi
    test rax, rax
    jne .ret
    mov rax, 1

.ret:
    mov rdx, [rdi +56]
    jmp rdx                  ; jump to saved return address

section .data
    seed dq 0