import re
import sys
from assembler import get_code

import requests

import urllib.parse


def get_answer_from_site(input):
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

    response = requests.request("POST", url, data=payload, headers=headers)
    answer = re.findall(r"\d:\s&nbsp;([\w\s]+)\s", response.text)
    result = "".join(answer)
    result = result.replace(" ", "").strip()
    return result


test_cases = [
    "mov al,bh",
    "mov dl,bl",
    "mov ecx,eax",
    "mov cl,al",
    "mov cx,ax",
    "mov dx,0x1352",
    "mov dx,0x3545",
    "mov edx,DWORD PTR [eax+ecx*1]",
    "mov edx,DWORD PTR [eax+ecx*1+0x55]",
    "mov edx,DWORD PTR [ecx*4]",
    "mov edx,DWORD PTR [ecx*4+0x06]",
    "mov edx,DWORD PTR [ebp+ecx*4]",
    "mov edx,DWORD PTR [ebx+ecx*4]",
    "mov edx,DWORD PTR [ebp+ecx*4+0x06]",
    "mov edx,DWORD PTR [ebp+ecx*4+0x55555506]",
    "mov edx,DWORD PTR [0x5555551E]",
    "add ecx,eax",
    "add cx,ax",
    "adc dx,0x3545",
    "add edi,DWORD PTR [ebx]",
    "test r8d,edx",
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

for test in test_cases:
    my_code = get_code(test)
    from_site = get_answer_from_site(test)
    if my_code != from_site:
        print(f"wrong answer for {test}")
        print(f"site: {from_site}")
        print(f"my code: {my_code}")
        sys.exit()
