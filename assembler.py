from email.headerregistry import Address
import logging as logger
import pdb
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

ValidationErr = RuntimeError

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
    "r9": "001",
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


class MOD_16(Enum):

    NO_DISP = "00"
    DISP8 = "01"
    DISP16 = "10"
    REG_ADDR = "11"


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
    Memory = 2
    NOT_EXIST = 3


@dataclass
class OpCode:
    """OpCode class"""

    opcode: str
    w: Optional[int] = None
    skip_d: bool = False
    d: Optional[int] = None
    skip_s: bool = True
    flip_d: bool = False

    # reg is hardcoded
    reg: Optional[str] = None

    # which operand does rm codes
    rm_codes: Optional[int] = None

    # do not calculate rm
    rm: Optional[str] = None

    # do not include rm in final code
    skip_rm: bool = False

    # do not calculate mod
    mod: Optional[MOD_32] = None

    # does not include mod in final code
    skip_mod: bool = False

    # no use
    source_operand_number: Optional[int] = None
    dest_operand_number: Optional[int] = None


# Operation: Source: Destination
opcode_table: Dict[str, Dict[OperandTypes, Dict[OperandTypes, OpCode]]] = {
    "mov": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="100010",
                d=0,
            ),
        },
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="1011", skip_d=True, skip_mod=True, skip_rm=True
            ),
        },
        OperandTypes.Memory: {OperandTypes.REGISTER: OpCode(opcode="100010")},
    },
    "add": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="000000",
                d=0,
                mod=MOD_32.REG_ADDR,
            )
        },
        OperandTypes.Memory: {
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
            OperandTypes.Memory: OpCode(
                opcode="100001",
                d=0,
            ),
            OperandTypes.IMMEDIATE: OpCode(opcode="111101", d=1),
        }
    },
    "imul": {
        OperandTypes.Memory: {
            OperandTypes.REGISTER: OpCode(opcode="00001111101011", d=1),
        }
    },
    "xor": {
        OperandTypes.Memory: {
            OperandTypes.REGISTER: OpCode(opcode="001100"),
        }
    },
    "xadd": {
        OperandTypes.REGISTER: {
            OperandTypes.Memory: OpCode(opcode="00001111110000"),
        }
    },
    "bsf": {
        OperandTypes.Memory: {
            OperandTypes.REGISTER: OpCode(
                opcode="00001111101111", d=0, w=0, flip_d=True
            ),
        }
    },
    "idiv": {
        OperandTypes.Memory: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111101",
                source_operand_number=1,
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
                rm_codes=1,
                d=1,
            )
        },
        OperandTypes.Memory: {
            OperandTypes.NOT_EXIST: OpCode(
                opcode="111111",
                reg="100",
                rm_codes=1,
                d=1,
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
            return OperandTypes.Memory
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
        """
        = 7
        """
        if "PTR" in self._raw:
            address = self._get_address()
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
                raise ValidationErr(f"Unknown Addressing mode {self._raw}")

        elif self._raw.startswith("0x"):
            return AddressingModes.IMM_ADDR
        elif is_register(self._raw):
            return AddressingModes.REG_ADDR
        else:
            raise ValueError(f"Unknown addressing mode {self._raw}")

    def get_size(self) -> int:
        if self.get_type() == OperandTypes.REGISTER:
            return get_register_size(self._raw)

        if self.get_type() == OperandTypes.Memory:
            reg = self.get_registers_used()
            if reg:
                return get_register_size(reg[0])

            # REMOVE
            if self.get_addressing_mode() == AddressingModes.DIRECT_ADDR_VALUE:
                if "BYTE" in self._raw:
                    return 8
                elif "WORD" in self._raw:
                    return 16
                elif "DWORD" in self._raw:
                    return 32
                elif "QWORD" in self._raw:
                    return 64

        raise RuntimeError(
            f"cannot get address size for this operand {self._raw}"
        )

    def get_base(self) -> Optional[str]:
        if self.get_addressing_mode() not in [
            AddressingModes.REG_INDIRECT_ADDR_BASE_DISP,
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX,
            AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX_DISP,
            AddressingModes.DIRECT_ADDR_REGISTER,
        ]:
            return None

        return self._get_address().split("+")[0]

    def get_index(self) -> Optional[str]:
        addr = self._get_address()
        components = addr.split("+")
        for comp in components:
            if "*" in comp:
                return comp.split("*")[0]
        return None

    def get_scale(self) -> Optional[int]:
        addr = self._get_address()
        components = addr.split("+")
        for comp in components:
            if "*" in comp:
                return int(comp.split("*")[1], 16)
        return None

    def get_disp(self) -> Optional[int]:
        addr = self._get_address()
        components = addr.split("+")
        for comp in components:
            if comp.startswith("0x"):
                return int(comp, 16)

    def get_disp_size(self) -> int:
        disp = self.get_disp()
        if disp is None:
            return 0
        disp_size = len(bin(disp)) - 1
        if disp_size <= 8:
            return 8
        elif disp_size <= 32:
            return 32
        else:
            raise RuntimeError(f"Unknown displacement size: {disp_size}")

    def _get_address(self) -> str:
        return self._raw.split("[")[1].removesuffix("]")


@dataclass
class Input:
    """Validates and Accesses the input"""

    operation: str
    first_operand: Optional[Operand]
    second_operand: Optional[Operand]

    def get_operation_used_registers_size(self) -> int:
        if self.first_operand is None:
            raise ValueError(f"No operands for {self.operation}")
        if self.first_operand.get_type() in [
            OperandTypes.Memory,
            OperandTypes.REGISTER,
        ]:
            return self.first_operand.get_size()
        elif self.second_operand and self.second_operand.get_type() in [
            OperandTypes.Memory,
            OperandTypes.REGISTER,
        ]:
            return self.second_operand.get_size()
        else:
            raise ValidationErr(f"No size for this operation {input}")

    def get_addressing_mode(self) -> AddressingModes:
        if self.second_operand is None:
            raise ValueError(f"No operands for {self.operation}")

        if self.first_operand is None:
            if self.second_operand.get_type() == OperandTypes.REGISTER:
                return AddressingModes.REG_ADDR
            elif self.second_operand.get_type() == OperandTypes.IMMEDIATE:
                return AddressingModes.IMM_ADDR
            else:
                raise NotImplementedError(
                    f"Unknown operand type: {self.second_operand}"
                )

        if (
            self.second_operand.get_type() == OperandTypes.REGISTER
            and self.first_operand.get_type() == OperandTypes.REGISTER
        ):
            return AddressingModes.REG_ADDR
        elif (
            self.second_operand.get_type() == OperandTypes.IMMEDIATE
            and self.first_operand.get_type() == OperandTypes.REGISTER
        ):
            return AddressingModes.IMM_ADDR
        else:
            raise NotImplementedError(
                f"Unknown operand types: {self.second_operand} {self.first_operand}"
            )


def parse_instruction(instruction: str) -> Input:
    """Parses a single instruction"""

    operation = instruction.split(" ")[0]

    logger.debug(f"operation is: {operation}")
    cursor = len(operation)

    while cursor < len(instruction) and instruction[cursor] != ",":
        cursor += 1

    first_operand = instruction[len(operation) + 1 : cursor]
    logger.debug(f"first operand is: {first_operand}")

    if cursor + 1 < len(instruction):
        second_operand = instruction[cursor + 1 :]
        second_operand = Operand(second_operand)
    else:
        second_operand = None
    logger.debug(f"second operand is: {second_operand}")

    return Input(operation, Operand(first_operand), second_operand)


def operand_require_rex(operand: Operand) -> bool:
    """Checks if the operand requires the rex prefix"""
    if operand.get_type() == OperandTypes.REGISTER:
        if operand.get_size() == 64 or operand.get_registers_used()[
            0
        ].startswith("r"):
            return True
    elif operand.get_type() == OperandTypes.Memory:
        for reg in operand.get_registers_used():
            if get_register_size(reg) == 64 or reg.startswith("r"):
                return True
    return False


def get_prefix(input: Input) -> Optional[str]:
    dest = input.second_operand
    src = input.first_operand

    size = 0
    address = 0
    for operand in [dest, src]:
        if operand is None:
            continue
        if operand.get_type() == OperandTypes.IMMEDIATE:
            continue
        size = operand.get_size()
        if operand.get_type() == OperandTypes.Memory:
            address = operand.get_size()
            logger.debug(f"operand {operand} size is {address}")

    prefix1 = operand_prefix_table[size]
    prefix2 = address_prefix_table.get(address, False)

    prefix = ""
    if prefix1 is True:
        prefix += str(SIZE_PREFIX)
    if prefix2 is True:
        prefix += str(ADDRESS_PREFIX)

    return prefix


def get_source_and_dest_operands(
    input: Input,
) -> Tuple[Optional[Operand], Optional[Operand]]:
    src = input.second_operand
    dest = input.first_operand

    if input.operation in ["idiv", "jmp"]:
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
        result = result.get(operand_src.get_type())
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

    src, dest = get_source_and_dest_operands(input)
    if get_opcode(input).d is not None:
        return get_opcode(input).d

    elif src and src.get_type() == OperandTypes.REGISTER:
        return 0
    elif dest and dest.get_type() == OperandTypes.REGISTER:
        return 1
    elif dest and dest.get_type() == OperandTypes.Memory:
        return 0
    elif src and src.get_type() == OperandTypes.Memory:
        return 1


def get_s(input: Input) -> Optional[int]:
    """Returns the s bit"""
    if not input.second_operand or not input.first_operand:
        return None
    if not input.second_operand.get_type() == OperandTypes.IMMEDIATE:
        return None

    imm_data_size = len(bin(input.second_operand.get_value()))

    if imm_data_size == 8 and input.first_operand.get_size() > 8:
        return 1

    return 0


def get_code_w(input: Input):
    """Returns the W value"""
    opcode = get_opcode(input)
    if opcode.w is not None:
        return opcode.w

    if input.get_operation_used_registers_size() == 8:
        return 0
    else:
        return 1


def get_mod(input: Input) -> Optional[MOD_32]:
    """Returns the MOD/RM value"""
    op_code = get_opcode(input)
    if op_code.mod is not None:
        return op_code.mod

    to_code = None
    d = get_d(input)
    if op_code.flip_d:
        d = int(not d)
    if d == 0:
        _, to_code = get_source_and_dest_operands(input)
    elif d == 1:
        to_code, _ = get_source_and_dest_operands(input)
    if to_code is None:
        raise RuntimeError(f"No operand to code")

    if to_code.get_type() == OperandTypes.Memory:
        addr_mod = to_code.get_addressing_mode()
        if addr_mod in [
            AddressingModes.DIRECT_ADDR_VALUE,
            AddressingModes.REG_INDIRECT_ADDR_INDEX,
        ]:
            return MOD_32.SIB
        elif addr_mod == AddressingModes.DIRECT_ADDR_REGISTER:
            if to_code.get_registers_used()[0].endswith("bp"):
                return MOD_32.DISP8
            return MOD_32.SIB
        elif addr_mod == AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX:
            if to_code.get_base().endswith("bp"):
                return MOD_32.DISP8
            return MOD_32.SIB
        elif addr_mod in [
            AddressingModes.REG_INDIRECT_ADDR_BASE_DISP,
        ]:
            if operand_require_rex(to_code):
                return MOD_32.get_mod_by_size(to_code.get_disp_size())
            return MOD_32.SIB
        elif addr_mod == AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX_DISP:
            return MOD_32.get_mod_by_size(to_code.get_disp_size())
        elif addr_mod == AddressingModes.REG_INDIRECT_ADDR_INDEX_DISP:
            return MOD_32.SIB

    elif to_code.get_type() == OperandTypes.REGISTER:
        return MOD_32.REG_ADDR
    else:
        raise NotImplementedError(f"Unknown operand type: {to_code}")


def select_operand_to_code_with_rm(input: Input) -> Optional[Operand]:
    to_code = None
    op_code = get_opcode(input)
    d = get_d(input)
    src, dest = get_source_and_dest_operands(input)
    if op_code.flip_d:
        d = int(not d)

    if d == 0:
        # rm codes the destination
        to_code = dest
    elif d == 1:
        # rm codes the source
        to_code = src

    op_code = get_opcode(input)
    if op_code.rm_codes == 1:
        to_code = input.first_operand
    elif op_code.rm_codes == 2:
        to_code = input.second_operand
    return to_code


def get_rm(input: Input):
    """Returns the RM value"""
    SIB = "100"
    to_code = select_operand_to_code_with_rm(input)

    if to_code is None:
        raise RuntimeError
    logger.debug(f"rm codes the {to_code}")

    if to_code.get_type() == OperandTypes.REGISTER:
        if operand_require_rex(to_code):
            return register_table_64[to_code.get_registers_used()[0]][1:]
        return rm_table_32_bit[to_code.get_registers_used()[0]]
    elif to_code.get_type() == OperandTypes.Memory:
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
    d = get_d(input)
    if op_code.flip_d:
        d = int(not d)

    if d == 0:
        return input.second_operand
    elif d == 1:
        return input.first_operand


def get_reg(input: Input) -> Optional[str]:
    """Returns the REG value"""
    opcode = get_opcode(input)
    if opcode.reg is not None:
        return opcode.reg
    to_code = select_operand_to_code_with_reg(input)
    if to_code is None:
        raise ValueError(f"No second operand for {to_code}")

    logger.debug(f"reg codes the {to_code}")

    if not to_code.get_type() == OperandTypes.REGISTER:
        raise ValueError(f"{to_code} is not a register")
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
        and input.first_operand.get_type() == OperandTypes.Memory
    ):
        to_code = input.first_operand
    elif (
        input.second_operand
        and input.second_operand.get_type() == OperandTypes.Memory
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


def reverse_byte_wise(binary: str) -> str:
    new_num = ""
    for i in range(0, len(str(binary)), 8):
        new_num = str(binary)[i : i + 8] + new_num
    return new_num


def get_data(input) -> Optional[str]:
    """Returns the data value"""
    if (
        input.second_operand
        and input.second_operand.get_type() == OperandTypes.IMMEDIATE
    ):
        return format(
            input.second_operand.get_value(),
            f"0{input.first_operand.get_size()}b",
        )


def get_disp(input: Input) -> Optional[str]:
    """Returns the displacement value"""
    to_code = select_operand_to_code_with_rm(input)
    if to_code is None:
        return None

    if to_code.get_type() != OperandTypes.Memory:
        return

    if (
        to_code.get_addressing_mode() == AddressingModes.DIRECT_ADDR_REGISTER
        and to_code.get_registers_used()[0].endswith("bp")
    ):
        return f"{0:08b}"

    if to_code.get_addressing_mode() in [
        AddressingModes.REG_INDIRECT_ADDR_INDEX,
        AddressingModes.REG_INDIRECT_ADDR_BASE_INDEX,
    ]:
        base = to_code.get_base()
        if base is None:
            return f"{0:032b}"
        elif base.endswith("bp"):
            return f"{0:08b}"
        else:
            return

    disp_value = to_code.get_disp()
    if disp_value is None:
        return

    logger.debug("found disp in operand")

    disp_size = len(bin(disp_value)) - 1

    base = to_code.get_base()
    # [0x55]
    if base is None:
        return f"{disp_value:032b}"
    # [ebp + 0x55]
    else:
        if disp_size <= 8:
            disp_size = 8
        else:
            disp_size = 32
        return f"{disp_value:0{disp_size}b}"


def get_r(input: Input) -> str:
    coded_with_reg = select_operand_to_code_with_reg(input)
    if coded_with_reg is None:
        return "0"
    return register_table_64[coded_with_reg.get_registers_used()[0]][0]


def get_rex_w(input: Input) -> int:
    if input.operation == "jmp":
        return 0
    for operand in [input.first_operand, input.second_operand]:
        if not operand:
            continue
        size = operand.get_size()
        if size in [8, 16, 32]:
            return 0
        else:
            return 1
    raise NotImplementedError("No operand specified")


def get_b(input: Input) -> str:
    mod = get_mod(input)
    op = select_operand_to_code_with_rm(input)
    if op is None:
        return ""
    addr_mode = op.get_addressing_mode()

    # rax
    # RM
    if addr_mode == AddressingModes.REG_ADDR:
        return register_table_64[op.get_registers_used()[0]][0]

    # if has a base field extend base
    base = op.get_base()
    if base is not None:
        return register_table_64[base][0]
    else:
        if op.get_size() == 64:
            return register_table_64["rbp"][0]
        return register_table_64["ebp"][0]


def get_x(input: Input) -> str:
    if not has_sib(input):
        return "0"

    operand = select_operand_to_code_with_rm(input)
    if not operand:
        return "0"

    index = operand.get_index()
    if index is None:
        raise ValueError("No index specified")
    return register_table_64[index][0]


def get_rex(input: Input) -> Optional[str]:
    # We only have rex if 64 bit operands or 32 bit operands starting with r are used
    need_rex = False
    to_code = None
    for operand in [input.first_operand, input.second_operand]:
        if operand is None:
            continue
        if operand_require_rex(operand):
            need_rex = True
            to_code = operand

    if not need_rex or not to_code:
        return None

    r = get_r(input)
    w = get_rex_w(input)
    b = get_b(input)
    x = get_x(input)

    print(f"r: {r}, w: {w}, b: {b}, x: {x}")

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

    data = get_data(input)
    if data is not None:
        formatted = reverse_byte_wise(data)
        print(f"data: {formatted}")
        result += formatted

    disp = get_disp(input)
    if disp is not None:
        print("disp raw: " + disp)
        formatted = reverse_byte_wise(disp)
        print(f"disp: {formatted}")
        result += formatted

    print(f"before hex: {result}")
    hex_value = hex(int("1" + result, 2))[3:]
    if prefix:
        hex_value = prefix + hex_value
    result = hex_value
    print(result)
    return result


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

# imul
assert get_code("imul r8w,WORD PTR [r14]") == "66450faf06"

# xor
assert get_code("xor r8b,BYTE PTR [rbp]") == "44324500"

# xadd
assert get_code("xadd QWORD PTR [rbx+0x5555551e],r10") == "4c0fc1931e555555"

assert get_code("xadd QWORD PTR [rbx*1+0x1],r10") == "4c0fc1141d01000000"

# bsf
assert get_code("bsf r11,QWORD PTR [r8+r12*4+0x16]") == "4f0fbc5ca016"

# idiv
assert get_code("idiv QWORD PTR [r11*4]") == "4af73c9d00000000"

# jmp
assert get_code("jmp r8") == "41ffe0"

assert get_code("jmp QWORD PTR [r8]") == "41ff20"


# assert get_code("jo hello") == "0f8000000000"

# cmp
# assert get_code("cmp r8, rdx") == "4939d0"
