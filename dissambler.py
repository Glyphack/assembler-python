from dataclasses import dataclass
from typing import Optional
from enum import Enum


class OperandSize(Enum):
    BYTE = "8"
    WORD = "16"
    DWORD = "32"
    QWORD = "64"


registers_table = {
    OperandSize.BYTE: {
        "0000": "al",
        "0001": "cl",
        "0010": "dl",
        "0011": "bl",
        "0100": "ah",
        "0101": "ch",
        "0110": "dh",
        "0111": "bh",
        "1000": "r8b",
        "1001": "r9b",
        "1010": "r10b",
        "1011": "r11b",
        "1100": "r12b",
        "1101": "r13b",
        "1110": "r14b",
        "1111": "r15b",
    },
    OperandSize.WORD: {
        "0000": "ax",
        "0001": "cx",
        "0010": "dx",
        "0011": "bx",
        "0100": "sp",
        "0101": "bp",
        "0110": "si",
        "0111": "di",
        "1000": "r8w",
        "1001": "r9w",
        "1010": "r10w",
        "1011": "r11w",
        "1100": "r12w",
        "1101": "r13w",
        "1110": "r14w",
        "1111": "r15w",
    },
    OperandSize.DWORD: {
        "0000": "eax",
        "0001": "ecx",
        "0010": "edx",
        "0011": "ebx",
        "0100": "esp",
        "0101": "ebp",
        "0110": "esi",
        "0111": "edi",
        "1000": "r8d",
        "1001": "r9d",
        "1010": "r10d",
        "1011": "r11d",
        "1100": "r12d",
        "1101": "r13d",
        "1110": "r14d",
        "1111": "r15d",
    },
    OperandSize.QWORD: {
        "0000": "rax",
        "0001": "rcx",
        "0010": "rdx",
        "0011": "rbx",
        "0100": "rsp",
        "0101": "rbp",
        "0110": "rsi",
        "0111": "rdi",
        "1000": "r8",
        "1001": "r9",
        "1010": "r10",
        "1011": "r11",
        "1100": "r12",
        "1101": "r13",
        "1110": "r14",
        "1111": "r15",
    },
}
mod_table = {"11": "64", "10": "32", "6610": "16", "00": "8"}


# prefix: code_w: rex_w
size_table = {
    "66": {
        "1": {
            "0": OperandSize.WORD,
        },
    },
    "": {
        "0": {"0": OperandSize.BYTE},
        "1": {"0": OperandSize.DWORD, "1": OperandSize.QWORD},
    },
}

scale_table = {"00": "1", "01": "2", "10": "4", "11": "8"}
sib_table = {
    "67": {
        "0000": "eax",
        "0001": "ecx",
        "0010": "edx",
        "0011": "ebx",
        "0100": "esp",
        "0101": "ebp",
        "0110": "esi",
        "0111": "edi",
        "1000": "r8d",
        "1001": "r9d",
        "1010": "r10d",
        "1011": "r11d",
        "1100": "r12d",
        "1101": "r13d",
        "1110": "r14d",
        "1111": "r15d",
    },
    "": {
        "0000": "rax",
        "0001": "rcx",
        "0010": "rdx",
        "0011": "rbx",
        "0100": "rsp",
        "0101": "rbp",
        "0110": "rsi",
        "0111": "rdi",
        "1000": "r8",
        "1001": "r9",
        "1010": "r10",
        "1011": "r11",
        "1100": "r12",
        "1101": "r13",
        "1110": "r14",
        "1111": "r15",
    },
}
ope_size_table = {
    OperandSize.BYTE: "BYTE",
    OperandSize.WORD: "WORD",
    OperandSize.DWORD: "DWORD",
    OperandSize.QWORD: "QWORD",
}

operations = {
    "mov": {
        "reg": "1000100",
        "mem": "1000101",
        "imm": {1: "1100011", 2: "11000"},
    },
    "add": {
        "reg": "0000000",
        "mem": "00000001",
        "imm": {1: "1000000", 2: "11000"},
    },
    "adc": {
        "reg": "0001000",
        "mem": "0001001",
        "imm": {1: "1000000", 2: "11000"},
    },
    "sub": {
        "reg": "0010100",
        "mem": "0010101",
        "imm": {1: "1000000", 2: "11101"},
    },
    "sbb": {
        "reg": "0001100",
        "mem": "0001101",
        "imm": {1: "1000000", 2: "11011"},
    },
    "and": {
        "reg": "0010000",
        "mem": "0010001",
        "imm": {1: "1000000", 2: "11100"},
    },
    "or": {
        "reg": "0000100",
        "mem": "0000101",
        "imm": {1: "1000000", 2: "11001"},
    },
    "xor": {
        "reg": "0011000",
        "mem": "0011001",
        "imm": {1: "1000000", 2: "11110"},
    },
    "cmp": {
        "reg": "0011100",
        "mem": "0011101",
        "imm": {1: "1000000", 2: "11111"},
    },
    "idiv": {
        "reg": "1111011",
        "mem": "111",
        "imm": {1: None, 2: None},
        "op_count": 1,
    },
    "neg": {
        "reg": "1111011",
        "mem": "011",
        "imm": {1: None, 2: None},
        "op_count": 1,
    },
    "not": {
        "reg": "1111011",
        "mem": "010",
        "imm": {1: None, 2: None},
        "op_count": 1,
    },
    "dec": {
        "reg": "1111111",
        "mem": "001",
        "imm": {1: None, 2: None},
        "op_count": 1,
    },
    "inc": {
        "reg": "1111111",
        "mem": "000",
        "imm": {1: None, 2: None},
        "op_count": 1,
    },
}


def hex_bin(hex_str):
    return bin(int("1" + str(hex_str), 16))[3:]


def format_binary_disp(binary_disp):
    if not binary_disp:
        return ""
    binary_disp = hex(int(binary_disp, 2))
    binary_disp = binary_disp[2:]
    hex_disp = ""
    if len(binary_disp) > 2:
        while binary_disp != "":
            hex_disp += binary_disp[len(binary_disp) - 2 :]
            binary_disp = binary_disp[: len(binary_disp) - 2]
        hex_disp = str(int(hex_disp))
    else:
        hex_disp = binary_disp
    return "0x" + hex_disp


def bin_to_decimal(binary_val):
    while True:
        if binary_val[-4:] == "0000":
            binary_val = binary_val[: len(binary_val) - 4]
        else:
            break
    if len(binary_val) % 8 != 0:
        binary_val += "0000"
    immediate_val = ""
    while len(binary_val) != 0:
        immediate_val += binary_val[-8:]
        binary_val = binary_val[: len(binary_val) - 8]
    immediate_val = str(int(immediate_val, 2))
    return immediate_val


@dataclass
class Prefix:
    pref_67: str = ""
    pref_66: str = ""
    rex: str = ""
    rex_w: str = "0"
    r: str = "0"
    x: str = "0"
    b: str = "0"

    def extract_legacy_prefix(self, input_str: str):
        if input_str[0:2] == "67":
            self.pref_67 = "67"
            input_str = input_str[2:]
        if input_str[0:2] == "66":
            self.pref_66 = "66"
            input_str = input_str[2:]
        input_str_without_legacy_prefix = input_str
        return input_str_without_legacy_prefix

    def extract_rex(self, input_str: str):
        if input_str[0:1] == "4":
            self.rex = input_str[:2]
            input_str = input_str[2:]
        input_str_without_rex_bin = input_str
        if self.rex:
            rex_binary = hex_bin(self.rex[1])
            self.rex_w = rex_binary[0]
            self.r = rex_binary[1]
            self.x = rex_binary[2]
            self.b = rex_binary[3]

        return input_str_without_rex_bin


def extract_prefixes(input_str: str):
    prefix = Prefix()
    input_str = prefix.extract_legacy_prefix(input_str)
    input_str = prefix.extract_rex(input_str)
    return input_str, prefix


def get_code_w(input_str: str):
    input_str_without_prefix, _ = extract_prefixes(input_str)
    code_w = hex_bin(input_str_without_prefix)[7:8]
    return code_w


def get_opcode(input_str: str):
    input_str_without_prefix, _ = extract_prefixes(input_str)
    opcode = hex_bin(input_str_without_prefix)[0:7]
    return opcode


def get_mod(input_str: str):
    input_str_without_prefix, _ = extract_prefixes(input_str)
    mod = hex_bin(input_str_without_prefix)[8:10]
    return mod


def get_rm(input_str: str):
    input_str_without_prefix, _ = extract_prefixes(input_str)
    rm = hex_bin(input_str_without_prefix)[13:16]
    return rm


def get_indirect_address(
    input_without_prefix_bin,
    prefix,
    rm,
    mod,
    operand_size,
    scale,
    base,
    index,
    displ,
):
    if mod != "11" and rm == "100":
        if mod == "00":
            if scale == "00" and base == "100" and index == "101":
                ope_size = ope_size_table[operand_size]
                return f"{ope_size} PTR [{displ}]"
            if base != "100" and index == "101":
                scale = scale_table[scale]
                index = sib_table[prefix.pref_67][prefix.x + base]
                ope_size = ope_size_table[operand_size]
                return (
                    f"{ope_size} PTR [{index} *{scale} + displ)]"
                    if displ
                    else ope_size + " PTR " + "[" + index + "*" + scale + "]"
                )
        else:
            scale = scale_table[scale]
            index = sib_table[prefix.pref_67][prefix.x + index]
            base = sib_table[prefix.pref_67][prefix.b + base]
            ope_size = ope_size_table[operand_size]
            return (
                f"{ope_size} PTR [{base}+{index}*{scale}+{displ}]"
                if displ
                else f"{ope_size} PTR [{base}+{index}*{scale}]"
            )

    base = sib_table[prefix.pref_67][prefix.b + rm]
    displ = format_binary_disp(input_without_prefix_bin[16:])
    ope_size = ope_size_table[operand_size]
    return (
        f"{ope_size} PTR [{base}+{displ}]"
        if displ
        else f"{ope_size} PTR [{base}]"
    )


def decode(encoded):
    input_str_without_prefix, prefix = extract_prefixes(encoded)
    input_without_prefix_bin = hex_bin(input_str_without_prefix)

    code_w = get_code_w(encoded)
    opcode_bin = get_opcode(encoded)
    rm = get_rm(encoded)
    mod = get_mod(encoded)
    reg = input_without_prefix_bin[10:13]

    operand_size = size_table[prefix.pref_66][code_w][prefix.rex_w]

    for inst, variation in operations.items():
        if variation.get("op_count") == 1:
            if (
                input_without_prefix_bin[0:7] == variation["reg"]
                and input_without_prefix_bin[10:13] == variation["mem"]
            ):

                if mod == "11":
                    return f"{inst} {registers_table[operand_size][prefix.b + rm]}"
                else:
                    dest = get_indirect_address(
                        input_without_prefix_bin,
                        prefix,
                        rm,
                        mod,
                        operand_size,
                        input_without_prefix_bin[16:18],
                        input_without_prefix_bin[18:21],
                        input_without_prefix_bin[21:24],
                        format_binary_disp(input_without_prefix_bin[24:]),
                    )
                    return f"{inst} {dest}"
        if variation.get("op_count") != 1:
            if opcode_bin == variation["reg"]:
                source_op = registers_table[operand_size][prefix.r + reg]
                if mod == "11":
                    dest = registers_table[operand_size][prefix.b + rm]
                else:
                    dest = get_indirect_address(
                        input_without_prefix_bin,
                        prefix,
                        rm,
                        mod,
                        operand_size,
                        input_without_prefix_bin[16:18],
                        input_without_prefix_bin[18:21],
                        input_without_prefix_bin[21:24],
                        format_binary_disp(input_without_prefix_bin[24:]),
                    )
                return f"{inst} {dest},{source_op}"
            if opcode_bin == variation["mem"]:
                dest = registers_table[operand_size][prefix.r + reg]
                source = get_indirect_address(
                    input_without_prefix_bin,
                    prefix,
                    rm,
                    mod,
                    operand_size,
                    input_without_prefix_bin[16:18],
                    input_without_prefix_bin[18:21],
                    input_without_prefix_bin[21:24],
                    format_binary_disp(input_without_prefix_bin[24:]),
                )
                return f"{inst} {dest},{source}"
            if (
                opcode_bin == variation["imm"][1]
                and input_without_prefix_bin[8:13] == variation["imm"][2]
            ):
                ime = input_without_prefix_bin[16:]
                ime = bin_to_decimal(ime)
                dest = registers_table[operand_size][prefix.b + rm]
                return f"{inst} {dest},{ime}"

    # Exceptional cases 15 bit long op codes
    opcode = input_without_prefix_bin[0:15]
    mod = input_without_prefix_bin[16:18]
    operand_size = size_table[prefix.pref_66][code_w][prefix.rex_w]
    if opcode == "000011111100000":
        if mod == "11":
            dest_reg = registers_table[operand_size][
                prefix.b + input_without_prefix_bin[21:24]
            ]
            source_reg = registers_table[operand_size][
                prefix.r + input_without_prefix_bin[18:21]
            ]
            return f"xadd {dest_reg}, {source_reg}"
        else:
            source_reg = registers_table[operand_size][
                prefix.r + input_without_prefix_bin[10:13]
            ]
            dest_mem = source = get_indirect_address(
                input_without_prefix_bin,
                prefix,
                rm,
                mod,
                operand_size,
                input_without_prefix_bin[16:18],
                input_without_prefix_bin[18:21],
                input_without_prefix_bin[21:24],
                format_binary_disp(input_without_prefix_bin[24:]),
            )
            return f"xadd {dest_mem}, {source_reg}"


i = input()
no_op = {
    "f9": "stc",
    "f8": "clc",
    "fd": "std",
    "fc": "cld",
    "c3": "ret",
    "0f05": "syscall",
}.get(i)
if no_op is not None:
    print(no_op)
else:
    result = decode(i)
    print(result)


# assert decode("89c8") == "mov eax,ecx"
# assert decode("4D8B01") == "mov r8,QWORD PTR [r9]"
# assert decode("49C7C07C000000") == "mov r8,124"
# print(decode("49F7D8"))
# assert decode("49F7D8") == "neg r8"
