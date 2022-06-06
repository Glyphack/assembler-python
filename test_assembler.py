import asyncio
import aiohttp
import re
import sys
from assembler import get_code, hex_to_binary, print_binary_formatted

import urllib.parse


async def get_answer_from_site(input, session):
    url = "https://defuse.ca/online-x86-assembler.htm"

    payload = (
        f"instructions={urllib.parse.quote(input)}&arch=x64&submit=Assemble"
    )
    headers = {
        "Accept-Language": "en-GB;q=0.7",
        "Cache-Control": "max-age=0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://defuse.ca",
        "Referer": "https://defuse.ca/online-x86-assembler.htm",
    }

    async with session.post(url, data=payload, headers=headers) as response:
        text = await response.text()
        answer = re.findall(r"\d:\s&nbsp;([\w\s]+)\s", text)
        result = "".join(answer)
        result = result.replace(" ", "").strip()
        return result


async def run_test(test_cases, operation=None):
    async with aiohttp.ClientSession() as session:
        for test in test_cases:
            if operation and not test.split(" ")[0] == operation:
                continue
            my_code = get_code(test)
            from_site = await get_answer_from_site(test, session)
            if not from_site:
                continue
            if my_code != from_site:
                print(f"wrong answer for {test}")
                print(f"site: {from_site}")
                print(f"my code: {my_code}")
                print("BINARY")
                print(
                    "g", print_binary_formatted(hex_to_binary("0x" + my_code))
                )
                print(
                    "e",
                    print_binary_formatted(hex_to_binary("0x" + from_site)),
                )
                sys.exit()


reg_to_reg_operands = [
    # reg to reg
    "al,bh",
    "dl,bl",
    "cl,al",
    "cx,ax",
    "ecx,eax",
]
reg_to_mem_operands = [
    "BYTE PTR[rax+rcx*1+0x94],cl",
    "QWORD PTR [rbx+0x5555551e],r10",
    "QWORD PTR [rbp+0x5555551e],r11",
    "QWORD PTR [rbx*1+0x1],r10",
    "QWORD PTR [ebp+0x5555551e],r11",
    "QWORD PTR [rax+rcx*1+0x94],rcx",
    "DWORD PTR [ecx*4],ebx",
]
imm_to_reg_operands = [
    # imm to reg
    "dx,0x1352",
    "dx,0x3545",
    # "rax,0x60",
    # "rax,0x95",
    # "rax,0x94",
    # "rax,0x79",
    # "rbx,0x5",
    # "rbx,0x95",
    # "rbx,0x94",
    # "rbx,0x79",
]
imm_to_mem_operands = [
    # imm to mem
    "WORD PTR [eax+ecx*1+0x94],0x5",
    "QWORD PTR [eax+ecx*1+0x94],0x5",
    "QWORD PTR [rcx*4+0x8],0x34",
]
mem_to_reg_operands = [
    # mem to reg
    "edx,DWORD PTR [ecx*4]",
    "edi,DWORD PTR [ebx]",
    "edx,DWORD PTR [ebp+ecx*4]",
    "edx,DWORD PTR [eax+ecx*1+0x55]",
    "edx,DWORD PTR [eax+ecx*1]",
    "edx,DWORD PTR [0x5555551E]",
    "edx,DWORD PTR [ecx*4+0x06]",
    "edx,DWORD PTR [ebx+ecx*4]",
    "edx,DWORD PTR [ebp+ecx*4+0x55555506]",
    "edx,DWORD PTR [ebp+ecx*4+0x06]",
    # mem to eax(edge case)
    "eax,DWORD PTR [ebp+ecx*4+0x06]",
    "rdx,QWORD PTR [rcx*4]",
    "rdi,QWORD PTR [rbx]",
    "rdx,QWORD PTR [ebp+ecx*4]",
    "rdx,QWORD PTR [eax+ecx*1+0x55]",
    "rdx,QWORD PTR [eax+ecx*1]",
    "rdx,QWORD PTR [0x5555551E]",
    "rdx,QWORD PTR [ecx*4+0x06]",
    "rdx,QWORD PTR [ebx+ecx*4]",
    "rdx,QWORD PTR [ebp+ecx*4+0x55555506]",
    "rdx,QWORD PTR [ebp+ecx*4+0x06]",
    "r11,QWORD PTR [r8+r12*4+0x16]",
    "r11,QWORD PTR [rbp+0x5555551e]",
    "r11,QWORD PTR [rbp+r12*1]",
    "r8w,WORD PTR [r14]",
    "r8b,BYTE PTR [rbp]",
    "r9w,WORD PTR[r14]",
    "r12,QWORD PTR [r8+r13*4+0x48]",
    "r12,QWORD PTR [rbx+r13*1]",
    "r12,QWORD PTR [rbx+r13*1+0x48]",
    "r12,QWORD PTR [rbp+r12*1]",
]


two_operands = (
    reg_to_reg_operands
    + imm_to_reg_operands
    + reg_to_mem_operands
    + mem_to_reg_operands
    + imm_to_mem_operands
)

single_operands = [
    "r9",
    "QWORD PTR [r9]",
    "r10",
    "QWORD PTR [0x5555551e]",
    "QWORD PTR [0x20]",
    "DWORD PTR [0x5555551e]",
    "r15",
    "QWORD PTR [r12*4]",
    "QWORD PTR [r9+r12*8]",
    "QWORD PTR [r10+r11*8]",
]

bsf_bsr = [
    "r12,QWORD PTR [r8+r13*4+0x48]",
    "r12,QWORD PTR [rbx+r13*1]",
    "r12,QWORD PTR [rbx+r13*1+0x48]",
    "r12,QWORD PTR [rbp+r12*1]",
] + mem_to_reg_operands

imul_cases = reg_to_reg_operands + reg_to_mem_operands + mem_to_reg_operands

instructions = [
    "mov",
    "add",
    "adc",
    "and",
    "cmp",
    "or",
    # "shl",
    # "shr",
    # "test",
    # "xor",
    # "sub",
    # "sbb",
]

one_operand_instructions = [
    "call",
    "dec",
    "inc",
    "idiv",
    "jmp",
    # "ret",
    # "not",
    # "neg",
    # "shl",
    # "shr",
]

test_cases = []
# normal two operands
for ins in instructions:
    for operand in two_operands:
        if ins == "or" and operand in [
            "rax,0x5",
            "rax,0x95",
            "rax,0x94",
            "rax,0x79",
        ]:
            continue
        test_cases.append(f"{ins} {operand}")

# bsf, bsr two operands
for ins in ["bsf", "bsr"]:
    for operand in bsf_bsr:
        test_cases.append(f"{ins} {operand}")

for ins in one_operand_instructions:
    for operand in single_operands:
        test_cases.append(f"{ins} {operand}")

for operand in imul_cases:
    test_cases.append(f"imul {operand}")

test_cases.extend(["stc", "clc", "std", "cld", "syscall", "ret"])

# all one operands
# no operands

# asyncio.run(run_test(test_cases, "add"))

asyncio.run(run_test(test_cases))
sample = [
    "mov WORD PTR[eax+ecx*1+0x94],0x5",
    "mov r11,QWORD PTR [r8+r12*4+0x16]",
    "mov edx,DWORD PTR [eax+ecx*1+0x55]",
    "mov edx,DWORD PTR [eax+ecx*1]",
    "mov r11,QWORD PTR [rbp+0x5555551e]",
    "mov al,bh",
    "mov edx,DWORD PTR [ebp+ecx*4+0x55555506]",
    "mov edx,DWORD PTR [ebp+ecx*4+0x06]",
    "mov BYTE PTR[rax+rcx*1+0x94],cl",
    "mov dx,0x1352",
    "mov r11,QWORD PTR [rbp+r12*1]",
    "mov dl,bl",
    "mov cx,ax",
    "mov QWORD PTR [ebp+0x5555551e],r11",
    "mov edx,DWORD PTR [0x5555551E]",
    "mov r8w,WORD PTR [r14]",
    "mov r8b,BYTE PTR [rbp]",
    "mov edi,DWORD PTR [ebx]",
    "mov edx,DWORD PTR [ebp+ecx*4]",
    "mov edx,DWORD PTR [ecx*4]",
    "mov ecx,eax",
    "mov cl,al",
    "mov QWORD PTR [rbx+0x5555551e],r10",
    "mov dx,0x3545",
    "mov edx,DWORD PTR [ecx*4+0x06]",
    "mov QWORD PTR [rbp+0x5555551e],r11",
    "mov edx,DWORD PTR [ebx+ecx*4]",
    "mov QWORD PTR [rbx*1+0x1],r10",
    "mov rax,0x60",
    "add ecx,eax",
    "add cx,ax",
    "add edi,DWORD PTR [ebx]",
    "add al,bh",
    "add dl,bl",
    "add ecx,eax",
    "add cl,al",
    "add cx,ax",
    "add dx,0x1352",
    "add dx,0x3545",
    "add edx,DWORD PTR [eax+ecx*1]",
    "add edx,DWORD PTR [eax+ecx*1+0x55]",
    "add edx,DWORD PTR [ecx*4]",
    "add edx,DWORD PTR [ecx*4+0x06]",
    "add edx,DWORD PTR [ebp+ecx*4]",
    "add edx,DWORD PTR [ebx+ecx*4]",
    "add edx,DWORD PTR [ebp+ecx*4+0x06]",
    "add edx,DWORD PTR [ebp+ecx*4+0x55555506]",
    "add edx,DWORD PTR [0x5555551E]",
    "add dx,0x3545",
    "add al,bh",
    "add dl,bl",
    "add ecx,eax",
    "add cl,al",
    "add cx,ax",
    "add dx,0x1352",
    "add dx,0x3545",
    "add edx,DWORD PTR [eax+ecx*1]",
    "add edx,DWORD PTR [eax+ecx*1+0x55]",
    "add edx,DWORD PTR [ecx*4]",
    "add edx,DWORD PTR [ecx*4+0x06]",
    "add edx,DWORD PTR [ebp+ecx*4]",
    "add edx,DWORD PTR [ebx+ecx*4]",
    "add edx,DWORD PTR [ebp+ecx*4+0x06]",
    "add edx,DWORD PTR [ebp+ecx*4+0x55555506]",
    "add edx,DWORD PTR [0x5555551E]" "dec QWORD PTR [0x5555551e]",
    "add WORD PTR[eax+ecx*1+0x94],0x5",
    "add QWORD PTR[rax+rcx*1+0x94],cl",
    "add QWORD PTR [rbp+0x5555551e],r11",
    "add r11,QWORD PTR [rbp+0x5555551e]",
    "add QWORD PTR [ebp+0x5555551e],r11",
    "add r8w,WORD PTR [r14]",
    "add r8b,BYTE PTR [rbp]",
    "add QWORD PTR [rbx+0x5555551e],r10",
    "add QWORD PTR [rbx*1+0x1],r10",
    "add r11,QWORD PTR [r8+r12*4+0x16]",
    "add r11,QWORD PTR [rbp+r12*1]",
    "adc dx,0x3545",
    "adc al,bh",
    "adc dl,bl",
    "adc ecx,eax",
    "adc cl,al",
    "adc cx,ax",
    "adc dx,0x1352",
    "adc dx,0x3545",
    "adc edx,DWORD PTR [eax+ecx*1]",
    "adc edx,DWORD PTR [eax+ecx*1+0x55]",
    "adc edx,DWORD PTR [ecx*4]",
    "adc edx,DWORD PTR [ecx*4+0x06]",
    "adc edx,DWORD PTR [ebp+ecx*4]",
    "adc edx,DWORD PTR [ebx+ecx*4]",
    "adc edx,DWORD PTR [ebp+ecx*4+0x06]",
    "adc edx,DWORD PTR [ebp+ecx*4+0x55555506]",
    "adc edx,DWORD PTR [0x5555551E]" "dec QWORD PTR [0x5555551e]",
    "adc WORD PTR[eax+ecx*1+0x94],0x5",
    "adc QWORD PTR[r8d+r9d*1+0x94]",
    "adc QWORD PTR[rax+rcx*1+0x94],cl",
    "adc QWORD PTR [rbp+0x5555551e],r11",
    "adc r11,QWORD PTR [rbp+0x5555551e]",
    "adc QWORD PTR [ebp+0x5555551e],r11",
    "adc r8w,WORD PTR [r14]",
    "adc r8b,BYTE PTR [rbp]",
    "adc QWORD PTR [rbx+0x5555551e],r10",
    "adc QWORD PTR [rbx*1+0x1],r10",
    "adc r11,QWORD PTR [r8+r12*4+0x16]",
    "adc r11,QWORD PTR [rbp+r12*1]",
    "adc r8d,edx",
    "test QWORD PTR [rbp+0x5555551e],r11",
    "test r11,QWORD PTR [rbp+0x5555551e]",
    "test QWORD PTR [ebp+0x5555551e],r11",
    "imul r8w,WORD PTR [r14]",
    "xor r8b,BYTE PTR [rbp]",
    "xadd QWORD PTR [rbx+0x5555551e],r10",
    "xadd QWORD PTR [rbx*1+0x1],r10",
    "bsf r11,QWORD PTR [r8+r12*4+0x16]",
    "bsr r11,QWORD PTR [rbp+r12*1]",
    "idiv QWORD PTR [r11*4]",
    "jmp r8",
    "jmp QWORD PTR [r8]",
    "jmp QWORD PTR[r9+r12*8+0x5716]",
    "cmp r8,rdx",
    "xchg r11,QWORD PTR [rbp+0x5555551e]",
    "xchg QWORD PTR [rbp+0x5555551e],r11",
    "sub DWORD PTR [ebp+ecx*4],edx",
    "sub QWORD PTR [rbp+rcx*4],rdx",
    "sbb QWORD PTR [rbp+rcx*4+0x94],rdx",
    "inc r10",
    "dec r10",
    "dec QWORD PTR [0x5555551e]",
    "dec QWORD PTR [0x20]",
    "dec DWORD PTR [0x5555551e]",
    "shl WORD PTR[eax+ecx*1+0x94],0x5",
    "shl QWORD PTR[r8d+r9d*1+0x94]",
    "shr QWORD PTR[rax+rcx*1+0x94],cl",
    "neg r11",
    "not QWORD PTR [r11]",
    "call r9",
    "call QWORD PTR [r9]",
    "ret",
    "ret 0x16",
    "push r12",
    "push QWORD PTR [r10+r11*8]",
    "pop r12",
    "pop QWORD PTR [r12]",
    "pop rax",
    "stc",
    "clc",
    "std",
    "cld",
    "syscall",
]
