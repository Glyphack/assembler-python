from assembler import get_code


# mov
assert get_code("mov al,bh") == "88f8"

assert get_code("mov dl,bl") == "88da"

assert get_code("mov ecx,eax") == "89c1"

assert get_code("mov cl,al") == "88c1"

assert get_code("mov cx,ax") == "6689c1"

assert (get_code("mov dx,0x1352")) == "66ba5213"

assert (get_code("mov dx,0x3545")) == "66ba4535"

assert get_code("mov edx,DWORD PTR [eax+ecx*1]") == "678b1408"

assert get_code("mov edx,DWORD PTR [eax+ecx*1+0x55]") == "678b540855"

assert get_code("mov edx,DWORD PTR [ecx*4]") == "678b148d00000000"

assert get_code("mov edx,DWORD PTR [ecx*4+0x06]") == "678b148d06000000"

assert get_code("mov edx,DWORD PTR [ebp+ecx*4]") == "678b548d00"

assert get_code("mov edx,DWORD PTR [ebx+ecx*4]") == "678b148b"

assert get_code("mov edx,DWORD PTR [ebp+ecx*4+0x06]") == "678b548d06"

assert (
    get_code("mov edx,DWORD PTR [ebp+ecx*4+0x55555506]") == "678b948d06555555"
)

assert get_code("mov edx,DWORD PTR [0x5555551E]") == "8b14251e555555"


# add
assert (get_code("add ecx,eax")) == "01c1"

assert get_code("add cx,ax") == "6601c1"

assert get_code("adc dx,0x3545") == "6681d24535"

assert get_code("add edi,DWORD PTR [ebx]") == "67033b"


# test
assert get_code("test r8d,edx") == "4185d0"

assert get_code("test QWORD PTR [rbp+0x5555551e],r11") == "4c859d1e555555"

assert get_code("test r11,QWORD PTR [rbp+0x5555551e]") == "4c859d1e555555"

assert get_code("test QWORD PTR [ebp+0x5555551e],r11") == "674c859d1e555555"

# imul
assert get_code("imul r8w,WORD PTR [r14]") == "66450faf06"

# xor
assert get_code("xor r8b,BYTE PTR [rbp]") == "44324500"

# xadd

assert get_code("xadd QWORD PTR [rbx+0x5555551e],r10") == "4c0fc1931e555555"

assert get_code("xadd QWORD PTR [rbx*1+0x1],r10") == "4c0fc1141d01000000"

# bsf

assert get_code("bsf r11,QWORD PTR [r8+r12*4+0x16]") == "4f0fbc5ca016"

# bsr

assert get_code("bsr r11,QWORD PTR [rbp+r12*1]") == "4e0fbd5c2500"

# idiv
assert get_code("idiv QWORD PTR [r11*4]") == "4af73c9d00000000"

# jmp
assert get_code("jmp r8") == "41ffe0"

assert get_code("jmp QWORD PTR [r8]") == "41ff20"

assert get_code("jmp QWORD PTR[r9+r12*8+0x5716]") == "43ffa4e116570000"

# assert get_code("jo hello") == "0f8000000000"

# cmp
assert get_code("cmp r8,rdx") == "4939d0"

# xchg

assert get_code("xchg r11,QWORD PTR [rbp+0x5555551e]") == "4c879d1e555555"

assert get_code("xchg QWORD PTR [rbp+0x5555551e],r11") == "4c879d1e555555"


# sub
assert get_code("sub DWORD PTR [ebp+ecx*4],edx") == "6729548d00"

assert get_code("sub QWORD PTR [rbp+rcx*4],rdx") == "4829548d00"

# sbb

assert get_code("sbb QWORD PTR [rbp+rcx*4+0x94],rdx") == "4819948d94000000"

# inc
assert get_code("inc r10") == "49ffc2"

# dec
assert get_code("dec r10") == "49ffca"

assert get_code("dec QWORD PTR [0x5555551e]") == "48ff0c251e555555"
assert get_code("dec QWORD PTR [0x20]") == "48ff0c2520000000"
assert get_code("dec DWORD PTR [0x5555551e]") == "ff0c251e555555"

# shl

assert get_code("shl WORD PTR[eax+ecx*1+0x94],0x5") == "6766c1a4089400000005"

assert get_code("shl QWORD PTR[r8d+r9d*1+0x94]") == "674bd1a40894000000"

# assert get_code("shl rax,0x1") == "48d1e0"

# shr

assert get_code("shr QWORD PTR[rax+rcx*1+0x94],cl") == "48d3ac0894000000"

# neg
assert get_code("neg r11") == "49f7db"

# not
assert get_code("not QWORD PTR [r11]") == "49f713"

# call
assert get_code("call r9") == "41ffd1"

assert get_code("call QWORD PTR [r9]") == "41ff11"

assert get_code("ret") == "c2"

assert get_code("ret 0x16") == "c21600"


# push
assert get_code("push r12") == "4154"

assert get_code("push QWORD PTR [r10+r11*8]") == "43ff34da"

# pop
assert get_code("pop r12") == "415c"

assert get_code("pop QWORD PTR [r12]") == "418f0424"

assert get_code("pop rax") == "58"


# stc
assert get_code("stc") == "f9"

# clc
assert get_code("clc") == "f8"

# std
assert get_code("std") == "fd"

# cld
assert get_code("cld") == "fc"

# syscall
assert get_code("syscall") == "0f05"
