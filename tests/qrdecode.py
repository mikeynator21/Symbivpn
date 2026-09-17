"""A QR reader, for checking that what the encoder draws can be read back.

Every existing QR test is structural: the finder patterns are present, the
timing rows alternate, a mask was chosen, the matrix is the right size. None
of them read the payload. A fault in data placement, in how the mask is
applied, or in the format field would satisfy all of them and still produce a
code no phone can scan -- on the one path a person uses to put their phone on
the VPN.

So this walks the other way: module grid in, payload out. It takes only
`QRCode.modules`, works out the version from the size and the mask from the
format field, rebuilds the function-pattern map from the standard's geometry,
reads the zigzag, undoes the interleaving and parses the bitstream.

It is not a general-purpose reader. It handles byte mode, which is what a
WireGuard configuration is, and it does no error correction: the data
codewords are read directly, so the test fails on any corruption rather than
quietly repairing it, which is what makes it a test.
"""

from __future__ import annotations

from symbivpn.vpn.qr import _ALIGNMENT_POSITIONS, _BLOCK_TABLE

#: Level bits as they appear in the format field, inverted from the encoder's
#: table so the field can be read rather than written.
_LEVEL_FROM_BITS = {0b01: "L", 0b00: "M", 0b11: "Q", 0b10: "H"}

_FORMAT_XOR = 0b101010000010010


class DecodeError(ValueError):
    """The matrix could not be read."""


def _function_modules(size: int, version: int) -> list[list[bool]]:
    """Which modules carry function patterns rather than data.

    Rebuilt from the standard's geometry rather than taken from the encoder,
    so that a mistake there shows up here as an unreadable code.
    """
    reserved = [[False] * size for _ in range(size)]

    def fill(top: int, left: int, height: int, width: int) -> None:
        for row in range(top, top + height):
            for column in range(left, left + width):
                if 0 <= row < size and 0 <= column < size:
                    reserved[row][column] = True

    # Finder patterns with their separators, and the format field beside each.
    fill(0, 0, 9, 9)
    fill(0, size - 8, 9, 8)
    fill(size - 8, 0, 8, 9)

    # Timing patterns run the full width and height.
    fill(6, 0, 1, size)
    fill(0, 6, size, 1)

    # Alignment patterns, except those that would sit on a finder.
    positions = _ALIGNMENT_POSITIONS.get(version, [])
    for row in positions:
        for column in positions:
            near_finder = (
                (row <= 8 and column <= 8)
                or (row <= 8 and column >= size - 9)
                or (row >= size - 9 and column <= 8)
            )
            if near_finder:
                continue
            fill(row - 2, column - 2, 5, 5)

    # The version field, present from version 7 upwards.
    if version >= 7:
        fill(size - 11, 0, 3, 6)
        fill(0, size - 11, 6, 3)

    return reserved


def read_format(modules: list[list[bool]]) -> tuple[str, int]:
    """The error-correction level and mask pattern, from the top-left copy."""
    bits = 0
    for position in range(15):
        if position < 6:
            row, column = 8, position
        elif position == 6:
            row, column = 8, 7
        elif position == 7:
            row, column = 8, 8
        elif position == 8:
            row, column = 7, 8
        else:
            row, column = 14 - position, 8
        if modules[row][column]:
            bits |= 1 << position

    value = bits ^ _FORMAT_XOR
    level_bits = (value >> 13) & 0b11
    mask = (value >> 10) & 0b111
    if level_bits not in _LEVEL_FROM_BITS:
        raise DecodeError(f"format field names no known level: {value:015b}")
    return _LEVEL_FROM_BITS[level_bits], mask


def _mask_condition(mask: int, row: int, column: int) -> bool:
    """The standard's eight mask patterns, written out again here.

    Deliberately a second copy: if the encoder's version and this one disagree,
    a payload encoded with one and read with the other will not survive, which
    is the whole point of reading it back.
    """
    if mask == 0:
        return (row + column) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return column % 3 == 0
    if mask == 3:
        return (row + column) % 3 == 0
    if mask == 4:
        return (row // 2 + column // 3) % 2 == 0
    if mask == 5:
        return (row * column) % 2 + (row * column) % 3 == 0
    if mask == 6:
        return ((row * column) % 2 + (row * column) % 3) % 2 == 0
    if mask == 7:
        return ((row + column) % 2 + (row * column) % 3) % 2 == 0
    raise DecodeError(f"mask pattern must be 0-7, got {mask}")


def _read_zigzag(modules, reserved, size: int, mask: int) -> list[int]:
    """Every data bit, in placement order, with the mask undone."""
    bits: list[int] = []
    upward = True
    column = size - 1
    while column > 0:
        if column == 6:
            column -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for offset in range(2):
                current = column - offset
                if reserved[row][current]:
                    continue
                value = modules[row][current]
                if _mask_condition(mask, row, current):
                    value = not value
                bits.append(1 if value else 0)
        upward = not upward
        column -= 2
    return bits


def _deinterleave(codewords: bytes, version: int, ec_level: str) -> bytes:
    """Undo the block interleaving and return the data codewords in order."""
    try:
        _, (blocks1, data1), (blocks2, data2) = _BLOCK_TABLE[(version, ec_level)]
    except KeyError:
        raise DecodeError(f"no block layout for version {version} level {ec_level}") from None

    lengths = [data1] * blocks1 + [data2] * blocks2
    blocks: list[list[int]] = [[] for _ in lengths]

    position = 0
    for index in range(max(lengths)):
        for block_number, length in enumerate(lengths):
            if index < length:
                if position >= len(codewords):
                    raise DecodeError("ran out of codewords while de-interleaving")
                blocks[block_number].append(codewords[position])
                position += 1

    return bytes(byte for block in blocks for byte in block)


def decode(modules: list[list[bool]]) -> bytes:
    """Read the payload back out of a rendered QR matrix."""
    size = len(modules)
    if size < 21 or (size - 17) % 4:
        raise DecodeError(f"{size}x{size} is not a valid QR size")
    version = (size - 17) // 4

    ec_level, mask = read_format(modules)
    reserved = _function_modules(size, version)
    bits = _read_zigzag(modules, reserved, size, mask)

    codewords = bytearray()
    for index in range(0, len(bits) - 7, 8):
        byte = 0
        for bit in bits[index : index + 8]:
            byte = (byte << 1) | bit
        codewords.append(byte)

    data = _deinterleave(bytes(codewords), version, ec_level)

    # Byte mode: a four-bit mode indicator, then the length, then the payload.
    stream = 0
    for byte in data:
        stream = (stream << 8) | byte
    total_bits = len(data) * 8

    def take(count: int, offset: int) -> int:
        shift = total_bits - offset - count
        return (stream >> shift) & ((1 << count) - 1)

    mode = take(4, 0)
    if mode != 0b0100:
        raise DecodeError(f"expected byte mode, got mode {mode:04b}")
    count_bits = 8 if version <= 9 else 16
    length = take(count_bits, 4)
    if length * 8 > total_bits - 4 - count_bits:
        raise DecodeError(f"declared length {length} does not fit the data")

    offset = 4 + count_bits
    return bytes(take(8, offset + index * 8) for index in range(length))
