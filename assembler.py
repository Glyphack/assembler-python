import logging as logger
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
from xml.dom import ValidationErr

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


def is_hex(string: str):
    return string.startswith("0x")


SIZE_PREFIX = 66
ADDRESS_PREFIX = 67
address_prefix_table = {
    64: False,
    32: True,
}

operand_prefix_table = {
    # (operand, address)
    64: False,
    32: False,
    16: True,
    8: False,
}

register_table_64 = {}
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


class MOD_16(Enum):
    """Mod values for 16bits"""

    NO_DISP = "00"
    DISP8 = "01"
    DISP16 = "10"
    REG_ADDR = "11"


class MOD_32(Enum):
    """Mod values for 32bits"""

    NO_DISP = "00"
    DISP8 = "01"
    DISP32 = "10"
    REG_ADDR = "11"


class AddressingModes(Enum):
    """Addressing modes

    Examples:
    REG_ADDR: `mov ax, bx`
    IMM_ADDR: `mov ax, 0x1234`
    DIRECT_ADDR: `mov ax, [0x1234]`
    REG_INDIRECT_ADDR: `mov ax, [bx+cx]`
    REG_INDIRECT_ADDR_DISP: `mov ax, [bx+cx+0x1234]`
    REG_INDIRECT_ADDR_DISP_SCALE: `mov ax, [bx+cx*8+18]`

    """

    REG_ADDR = 0
    IMM_ADDR = 1
    DIRECT_ADDR = 2
    REG_INDIRECT_ADDR = 3
    REG_INDIRECT_ADDR_DISP = 4


class OperandTypes(Enum):
    """Operand types only used for opcode"""

    REGISTER = 0
    IMMEDIATE = 1
    Memory = 2


@dataclass
class OpCode:
    """OpCode class"""

    opcode: str
    skip_d: bool = False
    d: Optional[int] = None
    skip_s: bool = True

    reg: Optional[str] = None
    skip_reg: bool = False

    rm: Optional[str] = None
    skip_rm: bool = False

    mod: Optional[MOD_32] = None
    skip_mod: bool = False


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
    },
    "add": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                opcode="000000",
                d=0,
                mod=MOD_32.REG_ADDR,
            )
        }
    },
    "adc": {
        OperandTypes.IMMEDIATE: {
            OperandTypes.REGISTER: OpCode(
                opcode="100000",
                skip_d=True,
                skip_s=False,
                mod=MOD_32.REG_ADDR,
                reg="010",
            ),
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
        elif "PTR" in self._raw and "+" in self._raw:
            return OperandTypes.Memory
        else:
            raise NotImplementedError(f"Unknown operand type: {self._raw}")

    def get_registers_used(self) -> List[str]:
        """Returns a list of registers used by this operand"""
        used = []
        tokenized = re.split("[, \+\*]+", self._raw)
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
        if "PTR" in self._raw:
            address = self._get_address()
            if is_register(address) or is_hex(address):
                return AddressingModes.DIRECT_ADDR
            elif "+" in self._raw or "*" in self._raw:
                return AddressingModes.REG_INDIRECT_ADDR
            elif is_hex(address.split("+")[-1]):
                return AddressingModes.REG_INDIRECT_ADDR_DISP
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
            if self._raw in REGISTER_64_BIT:
                return 64
            elif self._raw in REGISTER_16_BIT:
                return 16
            elif self._raw in REGISTER_32_BIT:
                return 32
            elif self._raw in REGISTER_8_BIT:
                return 8

        if self.get_type() == OperandTypes.Memory:
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
        addr = self._get_address()
        if "+" in self._raw:
            return self._raw.split("+")[0]

        # no + and * is direct addressing
        if "*" not in self._raw:
            return addr
        return None

    def get_index(self) -> str:
        addr = self._get_address()
        components = addr.split("+")
        for comp in components:
            if "*" in comp:
                return comp.split("*")[0]
        raise ValidationErr(f"index not found {self._raw}")

    def get_scale(self) -> int:
        addr = self._get_address()
        components = addr.split("+")
        for comp in components:
            if "*" in comp:
                return int(comp.split("*")[1], 16)
        raise ValidationErr(f"scale not found {self._raw}")

    def get_disp(self) -> int:
        addr = self._get_address()
        components = addr.split("+")
        for comp in components:
            if comp.startswith("0x"):
                return int(comp, 16)
        raise ValidationErr(f"disp not found {self._raw}")

    def _get_address(self) -> str:
        return self._raw.split("[")[1].removeprefix("]")


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

    # TODO: validate input

    while instruction[cursor] != ",":
        cursor += 1

    first_operand = instruction[len(operation) + 1 : cursor]
    logger.debug(f"first operand is: {first_operand}")

    second_operand = instruction[cursor + 1 :]
    logger.debug(f"second operand is: {second_operand}")

    return Input(operation, Operand(first_operand), Operand(second_operand))


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

    prefix1 = operand_prefix_table[size]
    prefix2 = address_prefix_table.get(address, False)

    prefix = ""
    if prefix1 is True:
        prefix += str(SIZE_PREFIX)
    if prefix2 is True:
        prefix += str(ADDRESS_PREFIX)

    return prefix


def get_opcode(input: Input) -> OpCode:
    """Returns the opcode"""
    operation = input.operation
    operand_dest = input.first_operand
    operand_src = input.second_operand
    operation_modes = opcode_table.get(operation)
    if not operation_modes:
        raise ValueError(f"Operation {operation} not found")
    result = operation_modes

    if operand_src:
        result = result.get(operand_src.get_type())

    if not result:
        raise ValueError(
            f"Operation {operation} with source operand type {operand_src} not found"
        )

    if operand_dest:
        result = result.get(operand_dest.get_type())

    if not result:
        raise ValueError(
            f"Operation {operation} with first operand type {operand_src} and second operand type {operand_dest} not found"
        )

    return result


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


def get_d(input: Input) -> Optional[int]:
    """Returns the D value"""
    if get_opcode(input).d is not None:
        logger.debug(f"opcode defined d itself {get_opcode(input).d}")
        return get_opcode(input).d
    elif (
        input.second_operand
        and input.second_operand.get_type() == OperandTypes.REGISTER
    ):
        return 0
    elif (
        input.first_operand
        and input.first_operand.get_type() == OperandTypes.REGISTER
    ):
        return 1


def get_code_w(input: Input):
    """Returns the W value"""
    if input.first_operand is None:
        return 1
    if input.second_operand is None:
        return None

    if input.operation in ["bsf", "bsr"]:
        return 0
    if input.get_operation_used_registers_size() == 8:
        return 0
    else:
        return 1


def get_mod(input: Input) -> Optional[MOD_32]:
    """Returns the MOD/RM value"""
    if input.second_operand is None:
        return None

    if input.first_operand is None:
        if input.second_operand.get_type() in [
            OperandTypes.Memory,
            OperandTypes.IMMEDIATE,
        ]:
            raise NotImplementedError(
                f"Unknown operand type: {input.second_operand}"
            )
        return MOD_32.REG_ADDR

    if OperandTypes.Memory in [
        input.second_operand.get_type(),
        input.first_operand.get_type(),
    ]:
        raise NotImplementedError()

    return MOD_32.REG_ADDR


def get_rm(input: Input):
    """Returns the RM value"""
    if input.second_operand is None:
        return None
    to_code = None
    if get_d(input) == 0:
        # rm codes the destination
        to_code = input.first_operand
    elif get_d(input) == 1:
        # rm codes the source
        to_code = input.first_operand
    else:
        raise NotImplementedError()

    if to_code is None:
        raise RuntimeError
    logger.debug(f"rm codes the {to_code}")

    if to_code.get_type() == OperandTypes.REGISTER:
        return rm_table_32_bit[to_code.get_registers_used()[0]]
    else:
        raise NotImplementedError()


def get_reg(input: Input) -> Optional[str]:
    """Returns the REG value"""
    if get_d(input) == 0:
        to_code = input.second_operand
        logger.debug(f"reg codes the {to_code}")
        if to_code is None:
            raise ValueError(f"No second operand for {to_code}")
        if to_code.get_type() == OperandTypes.REGISTER:
            return register_code_table_32[to_code.get_registers_used()[0]]
        else:
            raise NotImplementedError()
    else:
        to_code = input.first_operand
        logger.debug(f"reg codes the {to_code}")
        if to_code is None:
            raise ValueError(f"No first operand {to_code}")
        if to_code.get_type() == OperandTypes.REGISTER:
            return register_code_table_32[to_code.get_registers_used()[0]]
        else:
            raise NotImplementedError()


def reverse_byte_wise(binary: str) -> str:
    new_num = ""
    for i in range(len(str(binary)), 0, -8):
        new_num += str(binary)[i:]
    new_num += binary[0:8]
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


def get_code(asm_instruction: str):
    print("======================")
    input = parse_instruction(asm_instruction)
    print(input)
    op_code = get_opcode(input)
    print(asm_instruction)
    result = ""
    prefix = get_prefix(input)
    print(f"prefix {prefix}")

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

    if not op_code.skip_mod:
        mod = get_mod(input)
        if mod is not None:
            print(f"mod: {mod.value}")
            result += str(mod.value)

    reg = get_reg(input)
    if reg is not None:
        result += reg
    print(f"reg: {reg}")

    if not op_code.skip_rm:
        rm = get_rm(input)
        print(f"rm: {rm}")
        if rm is not None:
            result += rm

    data = get_data(input)
    if data is not None:
        formatted = reverse_byte_wise(data)
        print(f"data: {formatted}")
        result += formatted

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


# add
assert (get_code("add ecx,eax")) == "01c1"

assert get_code("add cx,ax") == "6601c1"

assert get_code("adc dx,0x3545") == "6681d24535"
