from audioop import add
import logging as logger
from dataclasses import dataclass
from enum import Enum
import re
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


@dataclass
class OpCode:
    """OpCode class"""

    opcode: str
    d: Optional[int]
    reg: Optional[str]
    has_s: bool = False
    has_d: bool = False


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


opcode_table: Dict[str, Dict[OperandTypes, Dict[OperandTypes, OpCode]]] = {
    "mov": {
        OperandTypes.REGISTER: {
            OperandTypes.REGISTER: OpCode(
                "100010",
                0,
                None,
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

    def operand_size(self) -> int:
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

    def get_used_register_size(self) -> int:
        """Returns the used register size in bits"""
        if set(self.get_registers_used()).issubset(REGISTER_64_BIT):
            return 64
        elif set(self.get_registers_used()).issubset(REGISTER_32_BIT):
            return 32
        elif set(self.get_registers_used()).issubset(REGISTER_16_BIT):
            return 16
        elif set(self.get_registers_used()).issubset(REGISTER_8_BIT):
            return 8
        else:
            raise ValueError(
                f"Unknown register size: {self.get_registers_used()}"
            )

    def _get_address(self) -> str:
        return self._raw.split("[")[1].removeprefix("]")


@dataclass
class Input:
    """Validates and Accesses the input"""

    operation: str
    dest_operand: Optional[Operand]
    first_operand: Optional[Operand]

    def get_operation_used_registers_size(self) -> int:
        if self.dest_operand is None:
            raise ValueError(f"No operands for {self.operation}")
        first_operand_register_size = (
            self.dest_operand.get_used_register_size()
        )

        if self.first_operand is None:
            return first_operand_register_size

        if (
            first_operand_register_size
            != self.first_operand.get_used_register_size()
        ):
            raise ValueError(
                f"Operands have different register sizes: {self.dest_operand} {self.first_operand}"
            )
        return first_operand_register_size

    def get_addressing_mode(self) -> AddressingModes:
        if self.dest_operand is None:
            raise ValueError(f"No operands for {self.operation}")

        if self.first_operand is None:
            if self.dest_operand.get_type() == OperandTypes.REGISTER:
                return AddressingModes.REG_ADDR
            elif self.dest_operand.get_type() == OperandTypes.IMMEDIATE:
                return AddressingModes.IMM_ADDR
            else:
                raise NotImplementedError(
                    f"Unknown operand type: {self.dest_operand}"
                )

        if (
            self.dest_operand.get_type() == OperandTypes.REGISTER
            and self.first_operand.get_type() == OperandTypes.REGISTER
        ):
            return AddressingModes.REG_ADDR
        elif (
            self.dest_operand.get_type() == OperandTypes.IMMEDIATE
            and self.first_operand.get_type() == OperandTypes.REGISTER
        ):
            return AddressingModes.IMM_ADDR
        else:
            raise NotImplementedError(
                f"Unknown operand types: {self.dest_operand} {self.first_operand}"
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


def get_opcode(
    operation: str,
    operand_dest: Optional[Operand],
    operand_src: Optional[Operand],
) -> OpCode:
    """Returns the opcode"""
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


def get_prefix(input: Input) -> Optional[str]:
    dest = input.dest_operand
    src = input.first_operand

    size = 0
    address = 0
    for operand in [dest, src]:
        if operand is None:
            continue
        size = operand.operand_size()
        if operand.get_type() == OperandTypes.Memory:
            address = operand.get_used_register_size()

    prefix1 = operand_prefix_table[size]
    prefix2 = address_prefix_table.get(address, False)

    prefix = ""
    if prefix1 is True:
        prefix += str(SIZE_PREFIX)
    if prefix2 is True:
        prefix += str(ADDRESS_PREFIX)

    return prefix


def get_d(input: Input) -> Optional[int]:
    """Returns the D value"""
    if input.first_operand is None:
        return 0

    if input.dest_operand is None:
        return 0

    op_code = get_opcode(
        input.operation,
        input.dest_operand,
        input.first_operand,
    )
    if op_code.has_s:
        return None

    if op_code.d is not None:
        return op_code.d

    if input.dest_operand.get_type() == OperandTypes.REGISTER:
        return 0

    elif input.first_operand.get_type() in [
        OperandTypes.Memory,
        OperandTypes.IMMEDIATE,
    ]:
        return 0


def get_code_w(input: Input):
    """Returns the W value"""
    if input.first_operand is None:
        return 1
    if input.dest_operand is None:
        return None

    if input.operation in ["bsf", "bsr"]:
        return 0
    if input.get_operation_used_registers_size() == 8:
        return 0
    else:
        return 1


def get_mod(input: Input) -> Optional[MOD_32]:
    """Returns the MOD/RM value"""
    if input.dest_operand is None:
        return None

    if input.first_operand is None:
        if input.dest_operand.get_type() in [
            OperandTypes.Memory,
            OperandTypes.IMMEDIATE,
        ]:
            raise NotImplementedError(
                f"Unknown operand type: {input.dest_operand}"
            )
        return MOD_32.REG_ADDR

    if OperandTypes.Memory in [
        input.dest_operand.get_type(),
        input.first_operand.get_type(),
    ]:
        raise NotImplementedError()

    return MOD_32.REG_ADDR


def get_rm(input: Input):
    """Returns the RM value"""
    if input.dest_operand is None:
        return None
    if get_d(input) == 0:
        # rm codes the destination
        logger.debug(f"rm codes the dest {input.dest_operand}")
        if input.dest_operand.get_type() == OperandTypes.REGISTER:
            return rm_table_32_bit[input.dest_operand.get_registers_used()[0]]
        else:
            raise NotImplementedError()
    else:
        raise NotImplementedError()


def get_reg(input: Input) -> Optional[str]:
    """Returns the REG value"""
    if input.dest_operand is None:
        return None
    if get_d(input) == 0:
        # reg codes the source
        logger.debug(f"reg codes the dest {input.first_operand}")
        if input.first_operand is None:
            raise ValueError(f"No second operand for {input.operation}")
        if input.first_operand.get_type() == OperandTypes.REGISTER:
            return register_code_table_32[
                input.first_operand.get_registers_used()[0]
            ]
        else:
            raise NotImplementedError()


def get_code(asm_instruction: str):
    print("======================")
    input = parse_instruction(asm_instruction)
    op_code = get_opcode(
        input.operation,
        input.dest_operand,
        input.first_operand,
    )
    print(asm_instruction)
    result = ""
    prefix = get_prefix(input)
    if prefix is not None:
        result += prefix

    result += op_code.opcode
    print(f"op: {op_code.opcode}")
    d = get_d(input)
    if d is not None:
        result += str(d)
    print(f"d:{d}")

    w = get_code_w(input)
    if w is not None:
        result += str(w)
    print(f"w: {w}")

    mod = get_mod(input)
    if mod is not None:
        print(f"mod: {mod.value}")
        result += str(mod.value)

    reg = get_reg(input)
    if reg is not None:
        result += reg
    print(f"reg: {reg}")

    rm = get_rm(input)
    print(f"rm: {rm}")
    if rm is not None:
        result += rm
    return result


assert get_code("mov al,bh") == "1000100011111000"

assert get_code("mov dl,bl") == "1000100011011010"

assert get_code("mov eax,ebx") == "1000100111011000"

print(get_code("mov al,cl"))
