import logging as logger
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger.basicConfig(level=logger.DEBUG)

REGISTER_8_BIT = {
    "al",
    "bl",
    "cl",
    "dl",
    "ah",
    "bh",
    "ch",
    "dh",
    "r8b",
    "r9b",
    "r10b",
    "r11b",
    "r12b",
    "r13b",
    "r14b",
    "r15b",
}

REGISTER_16_BIT = {
    "ax",
    "bx",
    "cx",
    "dx",
    "sp",
    "bp",
    "si",
    "di",
    "r8w",
    "r9w",
    "r10w",
    "r11w",
    "r12w",
    "r13w",
    "r14w",
    "r15w",
}

REGISTER_32_BIT = {
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",
}

REGISTER_64_BIT = {
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
}


def get_all_registers():
    """Returns all registers"""
    return [
        *REGISTER_8_BIT,
        *REGISTER_16_BIT,
        *REGISTER_32_BIT,
        *REGISTER_64_BIT,
    ]


def is_register(string):
    return string in get_all_registers()


def get_register_size(string) -> int:
    if string in REGISTER_64_BIT:
        return 64
    elif string in REGISTER_16_BIT:
        return 16
    elif string in REGISTER_32_BIT:
        return 32
    elif string in REGISTER_8_BIT:
        return 8
    else:
        raise ValueError(f"Invalid register {string}")


def is_hex(string: str):
    return string.startswith("0x")


def hex_to_binary(string: Union[str, int]) -> str:
    """converts 0xNUMBER to binary containing leading zeros"""
    return bin(int("1" + str(string)[2:], 16))[3:]


def get_binary_formatted(string: str):
    return " ".join(
        [string[::-1][i : i + 4] for i in range(0, len(string), 4)]
    )[::-1]


def reverse_byte_wise(binary: str) -> str:
    new_num = ""
    for i in range(0, len(str(binary)), 8):
        new_num = str(binary)[i : i + 8] + new_num
    return new_num


SIZE_PREFIX = 66
ADDRESS_PREFIX = 67
address_prefix_table = {
    64: False,
    32: True,
}

operand_prefix_table = {
    64: False,
    32: False,
    16: True,
    8: False,
}

register_table_64 = {
    "al": "0000",
    "cl": "0001",
    "dl": "0010",
    "bl": "0011",
    "ah": "0100",
    "ch": "0101",
    "dh": "0110",
    "bh": "0111",
    "r8b": "1000",
    "r9b": "1001",
    "r10b": "1010",
    "r11b": "1011",
    "r12b": "1100",
    "r13b": "1101",
    "r14b": "1110",
    "r15b": "1111",
    # 16 bit
    "ax": "0000",
    "cx": "0001",
    "dx": "0010",
    "bx": "0011",
    "sp": "0100",
    "bp": "0101",
    "si": "0110",
    "di": "0111",
    "r8w": "1000",
    "r9w": "1001",
    "r10w": "1010",
    "r11w": "1011",
    "r12w": "1100",
    "r13w": "1101",
    "r14w": "1110",
    "r15w": "1111",
    # 32 bit
    "eax": "0000",
    "ecx": "0001",
    "edx": "0010",
    "ebx": "0011",
    "esp": "0100",
    "ebp": "0101",
    "esi": "0110",
    "edi": "0111",
    "r8d": "1000",
    "r9d": "1001",
    "r10d": "1010",
    "r11d": "1011",
    "r12d": "1100",
    "r13d": "1101",
    "r14d": "1110",
    "r15d": "1111",
    # 64 bit
    "rax": "0000",
    "rcx": "0001",
    "rdx": "0010",
    "rbx": "0011",
    "rsp": "0100",
    "rbp": "0101",
    "rsi": "0110",
    "rdi": "0111",
    "r8": "1000",
    "r9": "1001",
    "r10": "1010",
    "r11": "1011",
    "r12": "1100",
    "r13": "1101",
    "r14": "1110",
    "r15": "1111",
}

register_code_table_32 = {
    # 8 bit
    "al": "000",
    "cl": "001",
    "dl": "010",
    "bl": "011",
    "ah": "100",
    "ch": "101",
    "dh": "110",
    "bh": "111",
    # 16 bit
    "ax": "000",
    "cx": "001",
    "dx": "010",
    "bx": "011",
    "sp": "100",
    "bp": "101",
    "si": "110",
    "di": "111",
    # 32 bit
    "eax": "000",
    "ecx": "001",
    "edx": "010",
    "ebx": "011",
    "esp": "100",
    "ebp": "101",
    "esi": "110",
    "edi": "111",
}

rm_table_32_bit = {
    "al": "000",
    "cl": "001",
    "dl": "010",
    "bl": "011",
    "ah": "100",
    "ch": "101",
    "dh": "110",
    "bh": "111",
    # 16 bit
    "ax": "000",
    "cx": "001",
    "dx": "010",
    "bx": "011",
    "sp": "100",
    "bp": "101",
    "si": "110",
    "di": "111",
    # 32 bit
    "eax": "000",
    "ecx": "001",
    "edx": "010",
    "ebx": "011",
    "esp": "100",
    "ebp": "101",
    "esi": "110",
    "edi": "111",
}

tttn_table = {
    "O": "0000",
    "NO": "0001",
    "B": "0010",
    "NAE": "0010",
    "NB": "0011",
    "AE": "0011",
    "E": "0100",
    "Z": "0100",
    "NE": "0101",
    "NZ": "0101",
    "BE": "0110",
    "NA": "0110",
    "A": "0111",
    "NBE": "0111",
    "S": "1000",
    "NS": "1001",
    "P": "1010",
    "PE": "1010",
    "NP": "1011",
    "PO": "1011",
    "L": "1100",
    "NGE": "1100",
    "NL": "1101",
    "GE": "1101",
    "LE": "1110",
    "NG": "1110",
    "G": "1111",
    "NLE": "1111",
}


class MOD_32(Enum):

    NO_DISP = "00"
    SIB = "00"
    DISP8 = "01"
    DISP32 = "10"
    REG_ADDR = "11"

    @classmethod
    def get_mod_by_size(cls, size):
        if size == 8:
            return cls.DISP8
        elif size == 32:
            return cls.DISP32
        else:
            raise ValueError(f"Invalid size {size}")


SIB = "100"


class Scale(Enum):

    ONE = "00"
    TWO = "01"
    FOUR = "10"
    EIGHT = "11"


class AddressingModes(Enum):
    """Addressing modes

    Examples:
    REG_ADDR: `mov ax, bx`
    IMM_ADDR: `mov ax, 0x1234`
    DIRECT_ADDR: `mov ax, [0x1234]`
    DIRECT_ADDR_REGISTER: `mov ax, [ebx]`
    REG_INDIRECT_ADDR_BASE_INDEX: `mov ax, [bx+cx*1]`
    REG_INDIRECT_ADDR_BASE_INDEX_DISP: `mov ax, [bx+cx*8+18]`
    REG_INDIRECT_ADDR_BASE_DISP: `mov ax, [bx+cx*1+0x1234]`
    REG_INDIRECT_ADDR_INDEX_DISP: `mov ax, [bx+cx*1+0x1234*2]`
    REG_INDIRECT_ADDR_INDEX: `mov ax, [ecx*4]`

    """

    REG_ADDR = 0
    IMM_ADDR = 1

    DIRECT_ADDR_VALUE = 2
    DIRECT_ADDR_REGISTER = 3

    REG_INDIRECT_ADDR_INDEX = 4
    REG_INDIRECT_ADDR_INDEX_DISP = 5
    REG_INDIRECT_ADDR_BASE_INDEX = 6
    REG_INDIRECT_ADDR_BASE_INDEX_DISP = 7
    REG_INDIRECT_ADDR_BASE_DISP = 8


class OperandTypes(Enum):
    """Operand types only used for opcode"""

    REGISTER = 0
    IMMEDIATE = 1
    MEMORY = 2
    NOT_EXIST = 3


@dataclass
class OpCode:
    """OpCode class"""

    opcode: str
    w: Optional[int] = None
    d: Optional[int] = None
    reg: Optional[str] = None
    rm: Optional[str] = None
    mod: Optional[MOD_32] = None
    r: Optional[int] = None
    x: Optional[int] = None
    rex_w: Optional[int] = None

    rm_codes: Optional[int] = None
    reg_codes: Optional[int] = None

    skip_prefix: bool = False
    skip_rex: bool = False
    skip_d: bool = False
    skip_s: bool = True
    skip_w: bool = False
    skip_mod: bool = False
    skip_reg: bool = False
    skip_rm: bool = False

    disp_size: Optional[int] = None
    only_rex_new_register: bool = False
    b_extends_reg: bool = False
    use_small_disp: bool = False
    prefix_smaller_than_64_operands: bool = False
    complex_reg: Optional[Callable[[Any], str]] = None


# Operation: second: first
opcode_table: Dict[
    str, Dict[Union[OperandTypes, str], Dict[Union[OperandTypes, str], OpCode]]
] = {
    "mov": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="100010",
                d=0,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100010",
            ),
        },
        OperandTypes.IMMEDIATE: {
            # "rax": OpCode(
            #     opcode="110001", mod=MOD_32.REG_ADDR, reg="000", rm_codes=1
            # ),
            # "rbx": OpCode(
            #     opcode="110001", mod=MOD_32.REG_ADDR, reg="000", rm_codes=1
            # ),
            # for 64 bits
            "64": OpCode(
                opcode="110001", mod=MOD_32.REG_ADDR, reg="000", rm_codes=1
            ),
            # alternate encoding
            OperandTypes.REGISTER: OpCode(
                opcode="1011",
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                reg_codes=1,
                b_extends_reg=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="110001",
                d=1,
                reg="000",
                rm_codes=1,
            ),
        },
        OperandTypes.MEMORY: {OperandTypes.REGISTER: OpCode(opcode="100010")},
    },
    "add": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="000000",
                # d=0,
                mod=MOD_32.REG_ADDR,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="000000",
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="000000", d=1)
        },
        OperandTypes.IMMEDIATE: {
            "rax": OpCode(
                opcode="01001000100000",
                rm_codes=1,
                skip_rex=True,
                use_small_disp=True,
            ),
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                reg="000",
                # check
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                reg="000",
                # check
                rm_codes=1,
                use_small_disp=True,
            ),
        },
    },
    "adc": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="000100",
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="000100",
            ),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                mod=MOD_32.REG_ADDR,
                reg="010",
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                reg="010",
                rm_codes=1,
                use_small_disp=True,
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(
                opcode="000100",
            ),
        },
    },
    "and": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="001000",
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="001000",
            ),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                mod=MOD_32.REG_ADDR,
                reg="100",
                rm_codes=1,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                reg="100",
                rm_codes=1,
                use_small_disp=True,
                skip_d=True,
                skip_s=False,
            ),
        },
        OperandTypes.MEMORY: {OperandTypes.REGISTER: OpCode(opcode="001000")},
    },
    "bsf": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="0000111110111100", mod=MOD_32.REG_ADDR
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="00001111101111", d=0, w=0, rm_codes=2, reg_codes=1
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(
                opcode="00001111101111", d=0, w=0, rm_codes=2, reg_codes=1
            ),
        },
    },
    "bsr": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="00001111101111", d=0, w=1, rm_codes=2, reg_codes=1
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="00001111101111", d=0, w=1, reg_codes=1, rm_codes=2
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(
                opcode="00001111101111", d=0, w=1, rm_codes=2, reg_codes=1
            ),
        },
    },
    # operand size compatibilty
    "call": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.REGISTER: OpCode(
                opcode="111111",
                mod=MOD_32.REG_ADDR,
                d=1,
                w=1,
                reg="010",
                rm_codes=1,
                rex_w=0,
                prefix_smaller_than_64_operands=True,
                only_rex_new_register=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="111111",
                d=1,
                w=1,
                r=0,
                complex_reg=lambda x: "011"
                if x.first_operand.get_operand_size() == 32
                else "010",
                rm_codes=1,
                rex_w=0,
                prefix_smaller_than_64_operands=True,
                only_rex_new_register=True,
            ),
            OperandTypes.IMMEDIATE: OpCode(
                opcode="11101000",
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                skip_prefix=True,
                skip_reg=True,
                skip_rex=True,
                skip_s=True,
                skip_w=True,
                disp_size=32,
            ),
        }
    },
    "cmp": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="001110",
                d=0,
            ),
            OperandTypes.MEMORY: OpCode(opcode="001110", d=0),
            OperandTypes.IMMEDIATE: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                mod=MOD_32.REG_ADDR,
                reg="111",
                rm_codes=1,
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="001110"),
            OperandTypes.IMMEDIATE: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                mod=MOD_32.REG_ADDR,
                reg="111",
                rm_codes=1,
                use_small_disp=True,
            ),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                mod=MOD_32.REG_ADDR,
                reg="111",
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                reg="111",
                rm_codes=1,
                use_small_disp=True,
            ),
        },
    },
    "inc": {
        OperandTypes.REGISTER: {
            OperandTypes.NOT_EXIST: OpCode(opcode="111111", d=1, reg="000")
        },
        OperandTypes.MEMORY: {
            OperandTypes.NOT_EXIST: OpCode(opcode="111111", d=1, reg="000")
        },
    },
    "idiv": {
        OperandTypes.MEMORY: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111101",
                reg="111",
            )
        },
        OperandTypes.REGISTER: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111101", reg="111", mod=MOD_32.REG_ADDR, d=1
            )
        },
    },
    # one operand not supported
    "imul": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="00001111101011",
                d=1,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="00001111101011", d=1, reg_codes=2, rm_codes=1
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="00001111101011", d=1),
        },
    },
    # TODO: other jumps
    "jmp": {
        OperandTypes.REGISTER: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111111",
                reg="100",
                mod=MOD_32.REG_ADDR,
                d=1,
                r=0,
                x=0,
                rex_w=0,
                only_rex_new_register=True,
                prefix_smaller_than_64_operands=True,
            )
        },
        OperandTypes.MEMORY: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111111",
                complex_reg=lambda x: "101"
                if x.first_operand.get_operand_size() == 32
                else "100",
                d=1,
                r=0,
                rex_w=0,
                only_rex_new_register=True,
                prefix_smaller_than_64_operands=True,
            )
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="11101001",
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                skip_prefix=True,
                skip_reg=True,
                skip_rex=True,
                skip_s=True,
                skip_w=True,
                disp_size=32,
            )
        },
    },
    "or": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(opcode="000010"),
            OperandTypes.MEMORY: OpCode(opcode="000010"),
        },
        OperandTypes.MEMORY: {OperandTypes.REGISTER: OpCode(opcode="000010")},
        # i don't know
        OperandTypes.IMMEDIATE: {
            "rax": OpCode(
                opcode="01001000100000",
                skip_prefix=True,
                skip_rex=True,
                reg="001",
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                mod=MOD_32.REG_ADDR,
                reg="001",
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                reg="001",
                rm_codes=1,
                use_small_disp=True,
            ),
        },
    },
    "test": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="100001",
                d=0,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100001",
                d=0,
            ),
            OperandTypes.IMMEDIATE: OpCode(
                opcode="111101", d=1, reg="000", rm_codes=1
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(
                opcode="100001", d=0, rm_codes=2, reg_codes=1
            ),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="111101", d=1, reg="000", rm_codes=1
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="111101", d=1, reg="000", rm_codes=1
            ),
        },
    },
    "xor": {
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="001100"),
        },
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(opcode="001100"),
            OperandTypes.MEMORY: OpCode(opcode="001100"),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                reg="110",
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                reg="110",
                rm_codes=1,
                use_small_disp=True,
            ),
        },
    },
    "xadd": {
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(opcode="00001111110000"),
            OperandTypes.REGISTER: OpCode(opcode="00001111110000"),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="00001111110000"),
        },
    },
    "xchg": {
        "ax": {
            OperandTypes.REGISTER: OpCode(
                opcode="10010",
                reg_codes=1,
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                skip_rex=True,
                skip_s=True,
                skip_w=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100001", d=1, rm_codes=1, reg_codes=2
            ),
        },
        "eax": {
            OperandTypes.REGISTER: OpCode(
                opcode="10010",
                reg_codes=1,
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                skip_rex=True,
                skip_s=True,
                skip_w=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100001", d=1, rm_codes=1, reg_codes=2
            ),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="100001", d=1),
        },
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(
                opcode="100001", d=1, rm_codes=1, reg_codes=2
            ),
            OperandTypes.REGISTER: OpCode(
                opcode="100001", d=1, reg_codes=2, rm_codes=1
            ),
            "ax": OpCode(
                opcode="10010",
                reg_codes=1,
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                skip_rex=True,
                skip_s=True,
                skip_w=True,
            ),
            "eax": OpCode(
                opcode="10010",
                reg_codes=1,
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                skip_rex=True,
                skip_s=True,
                skip_w=True,
            ),
        },
    },
    "sub": {
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(opcode="001010"),
            OperandTypes.REGISTER: OpCode(opcode="001010"),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="001010"),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                mod=MOD_32.REG_ADDR,
                reg="101",
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                reg="101",
                use_small_disp=True,
                rm_codes=1,
            ),
        },
    },
    "sbb": {
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(opcode="000110"),
            OperandTypes.REGISTER: OpCode(opcode="000110"),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="000110"),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                mod=MOD_32.REG_ADDR,
                reg="011",
                rm_codes=1,
                use_small_disp=True,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100000",
                skip_s=False,
                skip_d=True,
                reg="011",
                use_small_disp=True,
                rm_codes=1,
            ),
        },
    },
    "dec": {
        OperandTypes.MEMORY: {
            OperandTypes.NOT_EXIST: OpCode(opcode="111111", d=1, reg="001")
        },
        OperandTypes.REGISTER: {
            OperandTypes.NOT_EXIST: OpCode(opcode="111111", d=1, reg="001")
        },
    },
    "shl": {
        OperandTypes.IMMEDIATE: {
            OperandTypes.MEMORY: OpCode(
                opcode="110000", reg="100", d=0, disp_size=8
            ),
            OperandTypes.REGISTER: OpCode(
                opcode="110000",
                reg="100",
                disp_size=8,
                rm_codes=1,
                mod=MOD_32.REG_ADDR,
                d=0,
            ),
        },
        OperandTypes.NOT_EXIST: {
            OperandTypes.MEMORY: OpCode(opcode="110100", reg="100", d=0),
            OperandTypes.REGISTER: OpCode(opcode="110100", reg="100", d=0),
        },
        "cl": {
            OperandTypes.REGISTER: OpCode(
                opcode="110100",
                reg="100",
                d=1,
                mod=MOD_32.REG_ADDR,
                rm_codes=1,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="110100", reg="100", d=1, rm_codes=1
            ),
        },
    },
    "shr": {
        OperandTypes.IMMEDIATE: {
            OperandTypes.MEMORY: OpCode(
                opcode="110000", reg="101", d=0, disp_size=8
            ),
            OperandTypes.REGISTER: OpCode(
                opcode="110000",
                reg="101",
                disp_size=8,
                rm_codes=1,
                mod=MOD_32.REG_ADDR,
                d=0,
            ),
        },
        OperandTypes.NOT_EXIST: {
            OperandTypes.MEMORY: OpCode(opcode="110100", reg="101", d=0),
            OperandTypes.REGISTER: OpCode(
                opcode="110100", reg="101", d=0, mod=MOD_32.REG_ADDR
            ),
        },
        "cl": {
            OperandTypes.REGISTER: OpCode(
                opcode="110100",
                reg="101",
                d=1,
                mod=MOD_32.REG_ADDR,
                rm_codes=1,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="110100", reg="101", d=1, rm_codes=1
            ),
        },
        "rcx": {
            OperandTypes.REGISTER: OpCode(
                opcode="110100",
                reg="101",
                d=1,
                mod=MOD_32.REG_ADDR,
                rm_codes=1,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="110100", reg="101", d=1, rm_codes=1
            ),
        },
        "rbx": {
            OperandTypes.REGISTER: OpCode(
                opcode="110100",
                reg="101",
                d=1,
                mod=MOD_32.REG_ADDR,
                rm_codes=1,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="110100", reg="101", d=1, rm_codes=1
            ),
        },
    },
    "neg": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.REGISTER: OpCode(
                opcode="111101", d=1, reg="011", rm_codes=1
            ),
            OperandTypes.MEMORY: OpCode(opcode="111101", reg="011"),
        }
    },
    "not": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.MEMORY: OpCode(
                opcode="111101", d=1, reg="010", rm_codes=1
            ),
            OperandTypes.REGISTER: OpCode(
                opcode="111101",
                d=1,
                reg="010",
                mod=MOD_32.REG_ADDR,
                rm_codes=1,
            ),
        }
    },
    "ret": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="11000011",
                skip_prefix=True,
                skip_rex=True,
                skip_d=True,
                skip_s=True,
                skip_w=True,
                skip_mod=True,
                skip_reg=True,
                skip_rm=True,
            ),
            OperandTypes.IMMEDIATE: OpCode(
                opcode="11000010",
                skip_prefix=True,
                skip_rex=True,
                skip_d=True,
                skip_s=True,
                skip_w=True,
                skip_mod=True,
                skip_reg=True,
                skip_rm=True,
                disp_size=16,
            ),
        }
    },
    "push": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.REGISTER: OpCode(
                opcode="01010",
                skip_mod=True,
                skip_rm=True,
                b_extends_reg=True,
                skip_d=True,
                skip_w=True,
                reg_codes=1,
                only_rex_new_register=True,
                rex_w=0,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="111111",
                d=1,
                w=1,
                reg="110",
                rm_codes=1,
                rex_w=0,
                only_rex_new_register=True,
            ),
        }
    },
    "pop": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.REGISTER: OpCode(
                opcode="01011",
                reg_codes=1,
                skip_d=True,
                skip_w=True,
                skip_mod=True,
                skip_rm=True,
                b_extends_reg=True,
                only_rex_new_register=True,
                rex_w=0,
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="100011",
                d=1,
                w=1,
                reg="000",
                rm_codes=1,
                rex_w=0,
                only_rex_new_register=True,
            ),
        }
    },
    "stc": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="11111001",
                skip_d=True,
                skip_mod=True,
                skip_reg=True,
                skip_rm=True,
                skip_prefix=True,
                skip_rex=True,
                skip_w=True,
            )
        }
    },
    "clc": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="11111000",
                skip_d=True,
                skip_mod=True,
                skip_reg=True,
                skip_rm=True,
                skip_prefix=True,
                skip_rex=True,
                skip_w=True,
            )
        }
    },
    "std": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="11111101",
                skip_d=True,
                skip_mod=True,
                skip_reg=True,
                skip_rm=True,
                skip_prefix=True,
                skip_rex=True,
                skip_w=True,
            )
        }
    },
    "cld": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="11111100",
                skip_d=True,
                skip_mod=True,
                skip_reg=True,
                skip_rm=True,
                skip_prefix=True,
                skip_rex=True,
                skip_w=True,
            )
        }
    },
    "syscall": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="0000111100000101",
                skip_d=True,
                skip_mod=True,
                skip_reg=True,
                skip_rm=True,
                skip_prefix=True,
                skip_rex=True,
                skip_w=True,
            )
        }
    },
}


@dataclass
class Operand:
    _raw: str

    def get_type(self) -> OperandTypes:
        """Returns the type of this operand"""
        if self._raw in get_all_registers():
            return OperandTypes.REGISTER
        elif self._raw.startswith("0x"):
            return OperandTypes.IMMEDIATE
        elif "PTR" in self._raw:
            return OperandTypes.MEMORY
        else:
            raise NotImplementedError(f"Unknown operand type: {self._raw}")

    def get_registers_used(self) -> List[str]:
        """Returns a list of registers used by this operand"""
        used = []
        tokenized = re.split("\[|\]|,| |\+|\*", self._raw)
        for token in tokenized:
            if token in get_all_registers():
                used.append(token)
        return used

    def get_value(self) -> int:
        if self.get_addressing_mode() == AddressingModes.IMM_ADDR:
            return int(self._raw, 16)
        raise RuntimeError(
            f"cannot access value for non immediate operand {self._raw}"
        )

    def get_addressing_mode(self) -> AddressingModes:
        address = self._get_address()
        if address:
            if is_register(address):
                return AddressingModes.DIRECT_ADDR_REGISTER
            elif is_hex(address):
                return AddressingModes.DIRECT_ADDR_VALUE
            elif (
                len(address.split("+")) == 2
                and is_register(address.split("+")[0])
                and is_hex(address.split("+")[1])
            ):
                return AddressingModes.REG_INDIRECT_ADDR_BASE_DISP
            elif (
                len(address.split("+")) == 2
                and is_register(address.split("+")[0])
                and is_register(address.split("+")[1].split("*")[0])
            ):
                return AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX
            elif (
                len(address.split("+")) == 3
                and is_register(address.split("+")[0])
                and is_register(address.split("+")[1].split("*")[0])
                and is_hex(address.split("+")[2])
            ):
                return AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX_DISP

            elif len(address.split("+")) == 1 and is_register(
                address.split("*")[0]
            ):
                return AddressingModes.REG_INDIRECT_ADDR_INDEX
            elif (
                len(address.split("+")) == 2
                and is_register(address.split("*")[0])
                and is_hex(address.split("+")[1])
            ):
                return AddressingModes.REG_INDIRECT_ADDR_INDEX_DISP
            else:
                raise ValueError(f"Unknown Addressing mode {self._raw}")

        elif self._raw.startswith("0x"):
            return AddressingModes.IMM_ADDR
        elif is_register(self._raw):
            return AddressingModes.REG_ADDR
        else:
            raise ValueError(f"Unknown addressing mode {self._raw}")

    def get_address_size(self) -> int:
        if self.get_type() == OperandTypes.REGISTER:
            return get_register_size(self._raw)

        if self.get_type() == OperandTypes.MEMORY:
            reg = self.get_registers_used()
            if reg:
                return get_register_size(reg[0])
            else:
                return 64

        if self.get_type() == OperandTypes.IMMEDIATE:
            size = len(hex_to_binary(self.get_value()))
            if size < 16:
                return 16
            elif size <= 32:
                return 32
            else:
                return 64
        raise RuntimeError(
            f"cannot get address size for this operand {self._raw}"
        )

    def get_operand_size(self) -> int:
        if self.get_type() == OperandTypes.REGISTER:
            return get_register_size(self._raw)

        if self.get_type() == OperandTypes.MEMORY:
            if "BYTE" in self._raw:
                return 8
            elif "QWORD" in self._raw:
                return 64
            elif "DWORD" in self._raw:
                return 32
            elif "WORD" in self._raw:
                return 16
        if self.get_type() == OperandTypes.IMMEDIATE:
            size = len(bin(int(self._raw, 16)))
            if size < 16:
                return 16
            elif size <= 32:
                return 32
            else:
                return 64
        raise NotImplementedError(f"Unknown operand type {self._raw}")

    def get_base(self) -> Optional[str]:
        address = self._get_address()
        if not address or self.get_addressing_mode() not in [
            AddressingModes.REG_INDIRECT_ADDR_BASE_DISP,
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX,
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX_DISP,
            AddressingModes.DIRECT_ADDR_REGISTER,
        ]:
            return None

        return address.split("+")[0]

    def get_index(self) -> Optional[str]:
        addr = self._get_address()
        if addr is None:
            return
        components = addr.split("+")
        for comp in components:
            if "*" in comp:
                return comp.split("*")[0]
        return None

    def get_scale(self) -> Optional[int]:
        addr = self._get_address()
        if addr is None:
            return
        components = addr.split("+")
        for comp in components:
            if "*" in comp:
                return int(comp.split("*")[1], 16)
        return None

    def get_disp(self) -> Optional[int]:
        addr = self._get_address()
        if addr is None:
            return
        components = addr.split("+")
        for comp in components:
            if comp.startswith("0x"):
                return int(comp, 16)

    def get_disp_size(self) -> int:
        disp = self.get_disp()
        if disp is None:
            return 0
        disp_size = len(hex_to_binary(disp))
        if disp <= 128:
            return 8
        elif disp <= 4294967296:
            return 32
        else:
            raise RuntimeError(f"Unknown displacement size: {disp_size}")

    def _get_address(self) -> Optional[str]:
        if self.get_type() == OperandTypes.MEMORY:
            return self._raw.split("[")[1].replace("]", "")


@dataclass
class Input:
    operation: str
    first_operand: Optional[Operand]
    second_operand: Optional[Operand]

    def get_operation_used_registers_size(self) -> int:
        if self.first_operand is None:
            raise ValueError(f"No operands for {self.operation}")
        if self.first_operand.get_type() in [
            OperandTypes.MEMORY,
            OperandTypes.REGISTER,
        ]:
            return self.first_operand.get_operand_size()
        elif self.second_operand and self.second_operand.get_type() in [
            OperandTypes.MEMORY,
            OperandTypes.REGISTER,
        ]:
            return self.second_operand.get_operand_size()
        else:
            raise ValueError(f"No size for this operation {input}")


def adjust_operands(operation: str, operand: Operand):
    if operand._raw.isnumeric():
        operand._raw = hex(int(operand._raw))
    if "[r13" in operand._raw and operand.get_disp() is None:
        logger.debug("added a 0 displacement because r13 is base")
        return Operand(operand._raw.replace("]", "+0x0]"))
    if operation in ["shl", "shr"]:
        if operand._raw == "0x1":
            operand = None
    if operation in ["call", "jmp"]:
        try:
            ope_type = operand.get_type()
        except:
            operand._raw = "0x0"
    return operand


def parse_instruction(instruction: str) -> Input:
    operation = instruction.split(" ")[0]

    logger.debug(f"operation is: {operation}")
    cursor = len(operation)

    while cursor < len(instruction) and instruction[cursor] != ",":
        cursor += 1

    first_operand = instruction[len(operation) + 1 : cursor].strip()
    if not first_operand:
        first_operand = None
    else:
        first_operand = Operand(first_operand)
        first_operand = adjust_operands(operation, first_operand)

    if cursor + 1 < len(instruction):
        second_operand = instruction[cursor + 1 :].strip()
        second_operand = Operand(second_operand)
        second_operand = adjust_operands(operation, second_operand)
    else:
        second_operand = None

    logger.debug(f"first operand is: {first_operand}")
    logger.debug(f"second operand is: {second_operand}")

    return Input(operation, first_operand, second_operand)


def instruction_require_rex(input: Input) -> bool:
    return operand_require_rex(input.first_operand) or operand_require_rex(
        input.second_operand
    )


def operand_require_rex(operand: Operand) -> bool:
    logger.debug(f"checking if {operand} requires rex")
    if operand.get_type() == OperandTypes.REGISTER:
        if operand.get_address_size() == 64 or operand.get_registers_used()[
            0
        ].startswith("r"):
            logger.debug(
                "require rex because operand with size 64 or a new operand is used"
            )
            return True
    elif operand.get_type() == OperandTypes.MEMORY:
        if operand.get_operand_size() == 64 and operand.get_registers_used():
            logger.debug(
                "require rex because memory with 64 bit register is used"
            )
            return True
        for reg in operand.get_registers_used():
            if reg.startswith("r") and reg[1].isnumeric():
                logger.debug(
                    "require rex because a new operand is used in memory addressing"
                )
                return True
        if operand.get_operand_size() == 64:
            logger.debug("require rex because 64 bit size memory is used")
            return True
    return False


def get_prefix(input: Input) -> Optional[str]:
    logger.debug("checking if prefix is required")
    if get_opcode(input).skip_prefix:
        logger.debug("prefix is not required for this opcode")
        return None
    dest = input.second_operand
    src = input.first_operand

    size = 0
    address = 0
    for operand in [dest, src]:
        if operand is None:
            continue
        if operand.get_type() in [
            OperandTypes.IMMEDIATE,
            OperandTypes.REGISTER,
        ]:
            size = operand.get_operand_size()
        elif operand.get_type() == OperandTypes.MEMORY:
            if operand.get_operand_size() > size:
                size = operand.get_operand_size()
            address = operand.get_address_size()
            if (
                operand.get_addressing_mode()
                == AddressingModes.DIRECT_ADDR_VALUE
            ):
                address = 64

    logger.debug(
        f"operand address size is {address} and operand size is {size}"
    )

    prefix1 = operand_prefix_table.get(size, False)
    if get_opcode(input).prefix_smaller_than_64_operands and size < 64:
        prefix1 = True
    prefix2 = address_prefix_table.get(address, False)
    # don't know
    # if get_opcode(input).prefix_smaller_than_64_operands and address < 64:
    # prefix2 = True

    prefix = ""
    if prefix1 is True:
        prefix = str(SIZE_PREFIX) + prefix
    if prefix2 is True:
        prefix = str(ADDRESS_PREFIX) + prefix

    return prefix


def get_source_and_dest_operands(
    input: Input,
) -> Tuple[Optional[Operand], Optional[Operand]]:
    dest = input.first_operand
    src = input.second_operand

    if input.operation in [
        "idiv",
        "jmp",
        "inc",
        "dec",
    ]:
        src = input.first_operand
        return src, None

    return src, dest


def get_opcode(input: Input) -> OpCode:
    operation = input.operation
    operand_src, operand_dest = get_source_and_dest_operands(input)
    operation_modes = opcode_table.get(operation)
    if not operation_modes:
        raise ValueError(f"Operation {operation} not found")
    result = operation_modes
    if operand_src:
        src_size = operand_src.get_operand_size()
        result = operation_modes.get(str(src_size))
        if not result or not operand_src.get_type() != OperandTypes.REGISTER:
            result = operation_modes.get(
                operand_src._raw
            ) or operation_modes.get(operand_src.get_type())

        if not result:
            raise ValueError(
                f"Operation {operation} with source operand type {operand_src.get_type()} not found"
            )
    else:
        result = result.get(OperandTypes.NOT_EXIST)
        if not result:
            raise ValueError(
                f"Operation {operation} without operands not found"
            )

    if operand_dest:
        result_with_dest = None
        dest_size = operand_dest.get_operand_size()
        result_with_dest = result.get(str(dest_size))
        if (
            not result_with_dest
            or operand_dest.get_type() != OperandTypes.REGISTER
        ):
            result_with_dest = result.get(operand_dest._raw) or result.get(
                operand_dest.get_type()
            )
        if not result_with_dest:
            raise ValueError(
                f"Operation {operation} with first operand type {operand_src} and second operand type {operand_dest} not found"
            )
        result = result_with_dest
    else:
        result = result.get(OperandTypes.NOT_EXIST)
        if not result:
            raise ValueError(
                f"Operation {operation} with single first operand type {operand_src}"
            )
    return result


def get_d(input: Input) -> Optional[int]:
    """d is 1 if first operand is register"""

    if get_opcode(input).skip_d:
        return None

    src, dest = get_source_and_dest_operands(input)
    if get_opcode(input).d is not None:
        return get_opcode(input).d

    elif src and src.get_type() == OperandTypes.REGISTER:
        return 0
    elif dest and dest.get_type() == OperandTypes.REGISTER:
        return 1
    elif dest and dest.get_type() == OperandTypes.MEMORY:
        return 0
    elif src and src.get_type() == OperandTypes.MEMORY:
        return 1


def get_s(input: Input) -> Optional[int]:
    if get_opcode(input).skip_s:
        return None
    if not input.second_operand or not input.first_operand:
        return None
    if not input.second_operand.get_type() == OperandTypes.IMMEDIATE:
        return None

    imm_data_size = len(hex_to_binary(hex(input.second_operand.get_value())))
    imm_value_size = get_imm_data_size(input)
    logger.debug(f"immediate data size is {imm_data_size}")
    if imm_value_size <= 8:
        return 1
    else:
        return 0
    if imm_data_size <= 8:
        return 1
    return 0


def get_code_w(input: Input):
    """Returns the W value"""
    opcode = get_opcode(input)
    if opcode.skip_w:
        logger.debug("w is not required")
        return None
    if opcode.w is not None:
        logger.debug("w is specified in opcode")
        return opcode.w

    if input.get_operation_used_registers_size() == 8:
        logger.debug(f"returning W=1 because operation uses 8 bit registers")
        return 0
    else:
        return 1


def get_mod(input: Input) -> Optional[MOD_32]:
    if get_opcode(input).mod is not None:
        logger.debug("mod specified in opcode")
        return get_opcode(input).mod

    to_code = select_operand_to_code_with_rm(input)

    if to_code is None:
        raise ValueError(f"No operand to code")
    logger.debug(f"mod codes {to_code}")
    addr_mod = to_code.get_addressing_mode()
    base = to_code.get_base()
    disp = to_code.get_disp()
    if to_code.get_type() == OperandTypes.REGISTER:
        logger.debug(f"mod is register addressing")
        return MOD_32.REG_ADDR

    if addr_mod in [
        AddressingModes.DIRECT_ADDR_VALUE,
        AddressingModes.REG_INDIRECT_ADDR_INDEX,
        AddressingModes.REG_INDIRECT_ADDR_INDEX_DISP,
    ]:
        logger.debug("mod uses sib")
        return MOD_32.SIB

    if base is not None and disp is None:
        if base.endswith("bp"):
            logger.debug("mod is disp8 because base is bp and disp is empty")
            return MOD_32.DISP8
        if addr_mod == AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX:
            logger.debug("mod is sib because base is not bp and disp is empty")
            return MOD_32.SIB
        return MOD_32.NO_DISP

    if addr_mod == AddressingModes.REG_INDIRECT_ADDR_BASE_DISP:
        # if instruction_require_rex(input):
        return MOD_32.get_mod_by_size(to_code.get_disp_size())
        return MOD_32.SIB

    if addr_mod == AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX_DISP:
        return MOD_32.get_mod_by_size(to_code.get_disp_size())


def select_operand_to_code_with_rm(input: Input) -> Optional[Operand]:
    src, dest = get_source_and_dest_operands(input)
    if get_opcode(input).rm_codes == 1:
        return dest
    elif get_opcode(input).rm_codes == 2:
        return src
    if get_d(input) == 0:
        return dest
    elif get_d(input) == 1:
        return src


def get_rm(input: Input):
    if get_opcode(input).skip_rm:
        return None
    if get_opcode(input).rm:
        return get_opcode(input).rm
    to_code = select_operand_to_code_with_rm(input)
    if to_code is None:
        raise RuntimeError
    logger.debug(f"rm codes the {to_code}")

    if to_code.get_type() == OperandTypes.REGISTER:
        if operand_require_rex(to_code):
            return register_table_64[to_code.get_registers_used()[0]][1:]
        return rm_table_32_bit[to_code.get_registers_used()[0]]
    elif to_code.get_type() == OperandTypes.MEMORY:
        if to_code.get_addressing_mode() in [
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX_DISP,
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX,
            AddressingModes.REG_INDIRECT_ADDR_INDEX_DISP,
            AddressingModes.REG_INDIRECT_ADDR_INDEX,
            AddressingModes.DIRECT_ADDR_VALUE,
        ]:
            return SIB
        return register_table_64[to_code.get_registers_used()[0]][1:]
    elif to_code.get_type() == OperandTypes.IMMEDIATE:
        return None
    else:
        raise NotImplementedError()


def select_operand_to_code_with_reg(input: Input) -> Optional[Operand]:
    op_code = get_opcode(input)
    if op_code.reg is not None:
        return None
    if op_code.reg_codes == 1:
        return input.first_operand
    elif op_code.reg_codes == 2:
        return input.second_operand

    if get_d(input) == 0:
        return input.second_operand
    elif get_d(input) == 1:
        return input.first_operand

    if input.first_operand.get_type() is OperandTypes.REGISTER:
        return input.first_operand
    else:
        return input.second_operand


def get_reg(input: Input) -> Optional[str]:
    opcode = get_opcode(input)
    if opcode.skip_reg:
        return None
    if opcode.reg is not None:
        return opcode.reg
    if opcode.complex_reg is not None:
        return opcode.complex_reg(input)

    to_code = select_operand_to_code_with_reg(input)
    if to_code is None:
        raise ValueError(f"No second operand for {to_code}")
    logger.debug(f"reg codes the {to_code}")

    if operand_require_rex(to_code):
        # The first character of this code is encoded in the REX prefix
        return register_table_64[to_code.get_registers_used()[0]][1:]
    return register_code_table_32[to_code.get_registers_used()[0]]


def get_scale(operand: Operand) -> Scale:
    scale_specified = operand.get_scale()
    if scale_specified is None:
        return Scale.ONE
    return {
        1: Scale.ONE,
        2: Scale.TWO,
        4: Scale.FOUR,
        8: Scale.EIGHT,
    }[scale_specified]


def get_index(operand: Operand) -> str:
    index = operand.get_index()
    logger.debug(f"index is {index}")
    if index is None:
        # encoding when no index is used
        return "100"
    logger.debug(f"index is register is {index}")
    return register_table_64[index][1:]


def get_base(operand: Operand) -> str:
    base_specified = operand.get_base()
    logger.debug(f"base is {base_specified}")

    if operand_require_rex(operand):
        if base_specified is None:
            base_specified = "rbp"
    if base_specified is None:
        base_specified = "ebp"
    return register_table_64[base_specified][1:]


def has_sib(input: Input) -> bool:
    return get_rm(input) == "100"


def get_sib(input: Input) -> Optional[str]:
    if not has_sib(input):
        return None
    to_code = None
    if (
        input.first_operand
        and input.first_operand.get_type() == OperandTypes.MEMORY
    ):
        to_code = input.first_operand
    elif (
        input.second_operand
        and input.second_operand.get_type() == OperandTypes.MEMORY
    ):
        to_code = input.second_operand
    if to_code is None:
        logger.debug("no SIB")
        return None

    logger.debug(f"sib codes the {to_code}")
    scale = str(get_scale(to_code).value)
    index = get_index(to_code)
    base = get_base(to_code)
    logger.debug(f"scale: {scale}, index: {index}, base: {base}")
    return scale + index + base


def select_operand_with_imm_data(input: Input) -> Optional[Operand]:
    imm_val_op = None
    other_op = None
    for op in [input.first_operand, input.second_operand]:
        if op and op.get_type() == OperandTypes.IMMEDIATE:
            imm_val_op = op
        else:
            other_op = op
    if imm_val_op is None:
        return
    return imm_val_op


def get_imm_data_size(input: Input) -> Optional[int]:
    other_op = input.first_operand
    imm_data_op = select_operand_with_imm_data(input)
    if imm_data_op is None:
        return
    if imm_data_op == other_op:
        other_op = input.second_operand
    if other_op is None:
        other_op = input.first_operand
    other_op_size = other_op.get_operand_size()
    size = other_op_size
    value = imm_data_op.get_value()

    if other_op_size > 16:
        logger.debug(
            f"immediate data is used with {other_op_size} bits operand extended to 32"
        )
        size = 32
    if get_opcode(input).disp_size:
        logger.debug(
            f"this operand codes immediate data  with {get_opcode(input).disp_size} bits displacement"
        )
        size = get_opcode(input).disp_size
    if get_opcode(input).use_small_disp:
        if value <= 128:
            logger.debug(
                f"immediate data is small enough use 8 bit displacement"
            )
            size = 8
        elif value <= 4294967296 and 32 <= other_op_size:
            logger.debug(
                f"immediate data 32 bit extended fits into other operand with size {other_op_size}"
            )
            size = 32
    return size


def get_data(input: Input) -> Optional[str]:
    imm_val_op = None
    for op in [input.first_operand, input.second_operand]:
        if op and op.get_type() == OperandTypes.IMMEDIATE:
            imm_val_op = op
    if imm_val_op is None:
        return
    logger.debug(f"coding immediate data {imm_val_op}")
    value = imm_val_op.get_value()
    real_value = hex_to_binary(hex(value))
    size = get_imm_data_size(input)
    return format(
        int(real_value, 2),
        f"0{size}b",
    )


def get_disp(input: Input) -> Optional[str]:
    to_code = select_operand_to_code_with_rm(input)
    if to_code is None:
        return None
    if to_code.get_type() != OperandTypes.MEMORY:
        return None

    base = to_code.get_base()
    disp_value = to_code.get_disp()
    disp_size = to_code.get_disp_size()

    if base is None:
        if disp_value is None:
            return f"{0:032b}"
        else:
            return f"{disp_value:032b}"

    if disp_value is None:
        if base.endswith("bp"):
            return f"{0:08b}"
        else:
            return

    return f"{disp_value:0{disp_size}b}"


def get_r(input: Input) -> str:
    if get_opcode(input).r is not None:
        return str(get_opcode(input).r)
    if get_opcode(input).b_extends_reg:
        return "0"
    coded_with_reg = select_operand_to_code_with_reg(input)
    if coded_with_reg is None:
        return "0"
    return register_table_64[coded_with_reg.get_registers_used()[0]][0]


def get_rex_w(input: Input) -> int:
    rex_w = get_opcode(input).rex_w
    if rex_w is not None:
        return rex_w
    for operand in [input.first_operand, input.second_operand]:
        if not operand:
            continue
        size = operand.get_operand_size()
        if size in [8, 16, 32]:
            return 0
        else:
            return 1
    raise NotImplementedError("No operand specified")


def get_b(input: Input) -> str:
    op = select_operand_to_code_with_rm(input)
    if get_opcode(input).b_extends_reg:
        op = select_operand_to_code_with_reg(input)
    if op is None:
        return "0"
    addr_mode = op.get_addressing_mode()

    if addr_mode == AddressingModes.REG_ADDR:
        return register_table_64[op.get_registers_used()[0]][0]

    # if has a base field extend base
    base = op.get_base()
    if base is not None:
        return register_table_64[base][0]
    else:
        if op.get_address_size() == 64:
            return register_table_64["rbp"][0]
        return register_table_64["ebp"][0]


def get_x(input: Input) -> str:
    if get_opcode(input).x is not None:
        return str(get_opcode(input).x)

    if not has_sib(input):
        return "0"

    operand = select_operand_to_code_with_rm(input)
    if not operand:
        return "0"

    index = operand.get_index()
    if index is None:
        return "0"
    return register_table_64[index][0]


def get_rex(input: Input) -> Optional[str]:
    if get_opcode(input).skip_rex:
        return
    need_rex = False
    for operand in [input.first_operand, input.second_operand]:
        if operand is None:
            continue
        if get_opcode(input).only_rex_new_register:
            new_reg = False
            for reg in operand.get_registers_used():
                if register_table_64.get(reg, "0")[0] == "1":
                    new_reg = True
            if new_reg is False:
                continue
        if operand_require_rex(operand):
            need_rex = True

    if not need_rex:
        return None

    r = get_r(input)
    w = get_rex_w(input)
    b = get_b(input)
    x = get_x(input)

    logger.debug(f"w: {w}, r: {r}, x: {x}, b: {b}")

    return "0100" + str(w) + r + x + b


def get_code(asm_instruction: str):
    logger.debug("======================")
    logger.debug(asm_instruction)
    input = parse_instruction(asm_instruction)
    logger.debug(input)
    op_code = get_opcode(input)
    logger.debug(op_code)
    result = ""

    prefix = get_prefix(input)
    logger.debug(f"prefix {prefix}")

    rex = get_rex(input)
    logger.debug(f"rex {rex}")
    if rex:
        result += rex

    result += op_code.opcode
    logger.debug(f"op: {op_code.opcode}")

    if not op_code.skip_d:
        d = get_d(input)
        if d is not None:
            result += str(d)
        logger.debug(f"d:{d}")

    if not op_code.skip_s:
        s = get_s(input)
        logger.debug(f"s:{s}")
        result += str(s)

    w = get_code_w(input)
    if w is not None:
        result += str(w)
    logger.debug(f"w: {w}")

    mod = None
    if not op_code.skip_mod:
        mod = get_mod(input)

        if mod is not None:
            logger.debug(f"mod: {mod.value}")
            result += str(mod.value)

    reg = get_reg(input)
    if reg is not None:
        result += reg
    logger.debug(f"reg: {reg}")

    rm = None
    if not op_code.skip_rm:
        rm = get_rm(input)
        logger.debug(f"rm: {rm}")
        if rm is not None:
            result += rm

    sib = get_sib(input)
    if sib is not None:
        result += sib

    disp = get_disp(input)
    if disp is not None:
        formatted = reverse_byte_wise(disp)
        logger.debug(f"disp: {formatted}")
        result += formatted

    data = get_data(input)
    if data is not None:
        formatted = reverse_byte_wise(data)
        logger.debug(f"data: {formatted}")
        result += formatted

    logger.debug(result)
    logger.debug(f"before hex: {get_binary_formatted(result)}")
    hex_value = hex(int("1" + result, 2))[3:]
    if prefix:
        hex_value = prefix + hex_value
    result = hex_value
    logger.debug(result)
    return result


line = input()
print(get_code(line))
