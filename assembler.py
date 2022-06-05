import logging as logger
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

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


def hex_bin(string: Union[str, int]) -> str:
    """converts 0xNUMBER to binary containing leading zeros"""
    return bin(int("1" + str(string)[2:], 16))[3:]


def print_binary_formatted(string: str):
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
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="1011",
                skip_d=True,
                skip_mod=True,
                skip_rm=True,
                reg_codes=1,
            ),
        },
        OperandTypes.MEMORY: {OperandTypes.REGISTER: OpCode(opcode="100010")},
    },
    "add": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="000000",
                d=0,
                mod=MOD_32.REG_ADDR,
            )
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="000000", d=1)
        },
    },
    "adc": {
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                mod=MOD_32.REG_ADDR,
                reg="010",
                rm_codes=1,
            ),
        }
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
            OperandTypes.IMMEDIATE: OpCode(opcode="111101", d=1),
        },
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(
                opcode="100001", d=0, rm_codes=2, reg_codes=1
            ),
        },
    },
    "imul": {
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="00001111101011", d=1),
        }
    },
    "xor": {
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="001100"),
        }
    },
    "xadd": {
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(opcode="00001111110000"),
        }
    },
    "bsf": {
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(
                opcode="00001111101111", d=0, w=0, rm_codes=2, reg_codes=1
            ),
        }
    },
    "bsr": {
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(
                opcode="00001111101111", d=0, w=1, rm_codes=2, reg_codes=1
            ),
        },
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(opcode="00001111101111", d=0, w=1),
            OperandTypes.MEMORY: OpCode(
                opcode="00001111101111", d=0, w=1, reg_codes=1, rm_codes=2
            ),
        },
    },
    "idiv": {
        OperandTypes.MEMORY: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111101",
                reg="111",
            )
        },
    },
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
            )
        },
        OperandTypes.MEMORY: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111111", reg="100", d=1, r=0, rex_w=0
            )
        },
    },
    "cmp": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="001110",
                d=0,
            )
        }
    },
    "xchg": {
        OperandTypes.MEMORY: {
            OperandTypes.REGISTER: OpCode(opcode="100001", d=1),
        },
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(
                opcode="100001", d=1, rm_codes=1, reg_codes=2
            ),
        },
    },
    "sub": {
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(opcode="001010"),
        }
    },
    "sbb": {
        OperandTypes.REGISTER: {
            OperandTypes.MEMORY: OpCode(opcode="000110"),
        }
    },
    "inc": {
        OperandTypes.REGISTER: {
            OperandTypes.NOT_EXIST: OpCode(opcode="111111", d=1, reg="000")
        }
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
            OperandTypes.MEMORY: OpCode(opcode="110000", reg="100", d=0),
        },
        OperandTypes.NOT_EXIST: {
            OperandTypes.MEMORY: OpCode(opcode="110100", reg="100", d=0)
        },
    },
    "shr": {
        "cl": {
            OperandTypes.MEMORY: OpCode(
                opcode="110100", reg="101", d=1, rm_codes=1
            )
        }
    },
    "neg": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.REGISTER: OpCode(
                opcode="111101", d=1, reg="011", rm_codes=1
            )
        }
    },
    "not": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.MEMORY: OpCode(
                opcode="111101", d=1, reg="010", rm_codes=1
            )
        }
    },
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
            ),
            OperandTypes.MEMORY: OpCode(
                opcode="111111", d=1, w=1, reg="010", rm_codes=1, rex_w=0
            ),
        }
    },
    "ret": {
        OperandTypes.NOT_EXIST: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="11000010",
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
                opcode="111111", d=1, w=1, reg="110", rm_codes=1, rex_w=0
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
                opcode="100011", d=1, w=1, reg="000", rm_codes=1, rex_w=0
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
            size = len(hex_bin(self.get_value()))
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
        disp_size = len(hex_bin(disp))
        if disp <= 128:
            return 8
        elif disp <= 4294967296:
            return 32
        else:
            raise RuntimeError(f"Unknown displacement size: {disp_size}")

    def _get_address(self) -> Optional[str]:
        if self.get_type() == OperandTypes.MEMORY:
            return self._raw.split("[")[1].removesuffix("]")


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
            return self.first_operand.get_address_size()
        elif self.second_operand and self.second_operand.get_type() in [
            OperandTypes.MEMORY,
            OperandTypes.REGISTER,
        ]:
            return self.second_operand.get_address_size()
        else:
            raise ValueError(f"No size for this operation {input}")


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

    if cursor + 1 < len(instruction):
        second_operand = instruction[cursor + 1 :].strip()
        second_operand = Operand(second_operand)
    else:
        second_operand = None

    logger.debug(f"first operand is: {first_operand}")
    logger.debug(f"second operand is: {second_operand}")

    return Input(operation, first_operand, second_operand)


def operand_require_rex(operand: Operand) -> bool:
    if operand.get_type() == OperandTypes.REGISTER:
        if operand.get_address_size() == 64 or operand.get_registers_used()[
            0
        ].startswith("r"):
            return True
    elif operand.get_type() == OperandTypes.MEMORY:
        for reg in operand.get_registers_used():
            if get_register_size(reg) == 64 or reg.startswith("r"):
                return True
        if operand.get_operand_size() == 64:
            return True
    return False


def get_prefix(input: Input) -> Optional[str]:
    if get_opcode(input).skip_prefix:
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
    prefix2 = address_prefix_table.get(address, False)

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

    if input.operation in ["idiv", "jmp", "inc", "dec"]:
        src = input.first_operand
        return src, None

    return src, dest


def get_opcode(input: Input) -> OpCode:
    """Returns the opcode"""
    operation = input.operation
    operand_src, operand_dest = get_source_and_dest_operands(input)
    operation_modes = opcode_table.get(operation)
    if not operation_modes:
        raise ValueError(f"Operation {operation} not found")
    result = operation_modes
    if operand_src:
        result = result.get(operand_src.get_type()) or result.get(
            operand_src._raw
        )

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
        result = result.get(operand_dest.get_type())
        if not result:
            raise ValueError(
                f"Operation {operation} with first operand type {operand_src} and second operand type {operand_dest} not found"
            )
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
    """Returns the s bit"""
    if get_opcode(input).skip_s:
        return None
    if not input.second_operand or not input.first_operand:
        return None
    if not input.second_operand.get_type() == OperandTypes.IMMEDIATE:
        return None

    imm_data_size = len(hex_bin(input.second_operand.get_value()))

    if imm_data_size == 8 and input.first_operand.get_address_size() > 8:
        return 1

    return 0


def get_code_w(input: Input):
    """Returns the W value"""
    opcode = get_opcode(input)
    if opcode.skip_w:
        return None
    if opcode.w is not None:
        return opcode.w

    if input.get_operation_used_registers_size() == 8:
        return 0
    else:
        return 1


def get_mod(input: Input) -> Optional[MOD_32]:
    if get_opcode(input).mod is not None:
        return get_opcode(input).mod

    to_code = select_operand_to_code_with_rm(input)

    if to_code is None:
        raise ValueError(f"No operand to code")

    addr_mod = to_code.get_addressing_mode()
    base = to_code.get_base()
    disp = to_code.get_disp()
    if to_code.get_type() == OperandTypes.REGISTER:
        return MOD_32.REG_ADDR

    if addr_mod in [
        AddressingModes.DIRECT_ADDR_VALUE,
        AddressingModes.REG_INDIRECT_ADDR_INDEX,
        AddressingModes.REG_INDIRECT_ADDR_INDEX_DISP,
    ]:
        return MOD_32.SIB

    if base is not None and disp is None:
        if base.endswith("bp"):
            return MOD_32.DISP8
        if addr_mod == AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX:
            return MOD_32.SIB
        return MOD_32.NO_DISP

    if addr_mod == AddressingModes.REG_INDIRECT_ADDR_BASE_DISP:
        if operand_require_rex(to_code):
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
            AddressingModes.REG_INDIRECT_ADDR_INDEX_DISP,
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX_DISP,
            AddressingModes.REG_INDIRECT_ADDR_INDEX,
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX,
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


def get_reg(input: Input) -> Optional[str]:
    opcode = get_opcode(input)
    if opcode.skip_reg:
        return None
    if opcode.reg is not None:
        return opcode.reg
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
        return register_table_64[base_specified][1:]
    if base_specified is None:
        base_specified = "ebp"

    return register_code_table_32[base_specified]


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
    print(f"scale: {scale}, index: {index}, base: {base}")
    return scale + index + base


def get_data(input: Input) -> Optional[str]:
    imm_val_op = None
    for op in [input.first_operand, input.second_operand]:
        if op and op.get_type() == OperandTypes.IMMEDIATE:
            imm_val_op = op
    if imm_val_op is None:
        return
    value = imm_val_op.get_value()
    real_value = hex_bin(hex(value))
    size = len(real_value)
    if size < 8:
        size = 8
    if get_opcode(input).disp_size:
        size = get_opcode(input).disp_size
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
            if register_table_64.get(operand._raw, "0")[0] == "0":
                continue
        if operand_require_rex(operand):
            need_rex = True

    if not need_rex:
        return None

    r = get_r(input)
    w = get_rex_w(input)
    b = get_b(input)
    x = get_x(input)

    print(f"w: {w}, r: {r}, x: {x}, b: {b}")

    return "0100" + str(w) + r + x + b


def get_code(asm_instruction: str):
    print("======================")
    print(asm_instruction)
    input = parse_instruction(asm_instruction)
    print(input)
    op_code = get_opcode(input)
    result = ""

    prefix = get_prefix(input)
    print(f"prefix {prefix}")

    rex = get_rex(input)
    print(f"rex {rex}")
    if rex:
        result += rex

    result += op_code.opcode
    print(f"op: {op_code.opcode}")

    if not op_code.skip_d:
        d = get_d(input)
        if d is not None:
            result += str(d)
        print(f"d:{d}")

    if not op_code.skip_s:
        s = get_s(input)
        result += str(s)

    w = get_code_w(input)
    if w is not None:
        result += str(w)
    print(f"w: {w}")

    mod = None
    if not op_code.skip_mod:
        mod = get_mod(input)

        if mod is not None:
            print(f"mod: {mod.value}")
            result += str(mod.value)

    reg = get_reg(input)
    if reg is not None:
        result += reg
    print(f"reg: {reg}")

    rm = None
    if not op_code.skip_rm:
        rm = get_rm(input)
        print(f"rm: {rm}")
        if rm is not None:
            result += rm

    sib = get_sib(input)
    if sib is not None:
        result += sib

    disp = get_disp(input)
    if disp is not None:
        formatted = reverse_byte_wise(disp)
        print(f"disp: {formatted}")
        result += formatted

    data = get_data(input)
    if data is not None:
        formatted = reverse_byte_wise(data)
        print(f"data: {formatted}")
        result += formatted

    print(f"before hex: {print_binary_formatted(result)}")
    hex_value = hex(int("1" + result, 2))[3:]
    if prefix:
        hex_value = prefix + hex_value
    result = hex_value
    print(result)
    return result
