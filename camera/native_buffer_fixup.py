# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0

from hashlib import sha256
from pathlib import Path
from struct import unpack_from


_BUILD_ID = bytes.fromhex('ec48961c6c7573bd5e4cfd9c7917ad11')
_FUNCTION = b'_ZN7android12ExynosCamera30m_startPictureBufferThreadFuncEv'
_FUNCTION_SIZE = 316
_ORIGINAL_HASH = 'fb269c4e226bb05c5658d47862cecd743349ad01f90fddee4ae870cc22e1ac91'
_PATCHED_HASH = '20a1c6664a65306240c634a2ac9c1a887ed9defb097700050d82d1d18fb586db'
_CALL_OFFSET = 0x98
_CALL = bytes.fromhex('daf7a8ff')
_NOPS = bytes.fromhex('00bf00bf')
_ISP_FUNCTION = b'_ZN7android12ExynosCamera12m_setBuffersEv'
_ISP_FUNCTION_SIZE = 2984
_ISP_HASHES = {
    '0da5bfb61413cdd5d6aec5ddc16ce6b5f1fec83c32eb65882d8b83cfd2d8c3b9': 'raw',
    'bf71eac28a1cff866d8c5b367dcef222c10c28f7219c1cc27d19823f1b2e9b88': 'fps',
    '1f30d5f35028c5fab9463fe3e98d5b1f9b8288603121ac1cb5f8470a919f7cd1': 'patched',
}
_ISP_OFFSET = 0x15c
_ISP_EDITS = (
    (0x146, bytes.fromhex('03f0f3fa'), bytes.fromhex('bef7dffe')),
    (0x15a, bytes.fromhex('2cd0'), bytes.fromhex('2cdd')),
    (0x15c,
     bytes.fromhex(
         '00955caa5bab0a2105f02ef9d8f8c830dde95b1044f2'
         '1112cde900a6cde9022004919a499a4a79447a442be0'),
     bytes.fromhex('012904d0dde956125c915b923de000955caa5bab0a2105f027f936e000bf00bf00bf00bf00bf00bf00bf00bf')),
)


def _range(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError('Truncated Note9 camera ELF')
    return data[offset:offset + size]


def _camera_function(data, name, size):
    if _range(data, 0, 7) != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected a little-endian ELF32 camera HAL')
    header = unpack_from('<HHIIIIIHHHHHH', _range(data, 16, 36))
    if header[:3] != (3, 40, 1) or (header[7], header[8], header[10]) != (52, 32, 40):
        raise ValueError('Expected an ARM shared camera HAL')
    segments = [unpack_from('<IIIIIIII', _range(data, header[4] + i * 32, 32))
                for i in range(header[9])]
    sections = [unpack_from('<IIIIIIIIII', _range(data, header[5] + i * 40, 40))
                for i in range(header[11])]

    build_ids = []
    for segment in segments:
        if segment[0] != 4:
            continue
        notes = _range(data, segment[1], segment[4])
        offset = 0
        while offset < len(notes):
            namesz, descsz, kind = unpack_from('<III', _range(notes, offset, 12))
            offset += 12
            note_name = _range(notes, offset, namesz)
            offset += (namesz + 3) & ~3
            descriptor = _range(notes, offset, descsz)
            offset += (descsz + 3) & ~3
            if note_name == b'GNU\0' and kind == 3:
                build_ids.append(descriptor)
    if build_ids != [_BUILD_ID]:
        raise ValueError('Unsupported Note9 camera HAL Build ID')

    symbols = []
    for section in sections:
        if section[1] != 11:
            continue
        if section[9] != 16 or section[5] % 16 or section[6] >= len(sections):
            raise ValueError('Invalid camera dynamic symbol table')
        strings = sections[section[6]]
        if strings[1] != 3:
            raise ValueError('Invalid camera dynamic string table')
        names = _range(data, strings[4], strings[5])
        for offset in range(section[4], section[4] + section[5], 16):
            symbol = unpack_from('<IIIBBH', _range(data, offset, 16))
            if symbol[0] >= len(names):
                raise ValueError('Invalid camera symbol name')
            end = names.find(b'\0', symbol[0])
            if end == -1:
                raise ValueError('Unterminated camera symbol name')
            if names[symbol[0]:end] == name:
                symbols.append(symbol)
    if len(symbols) != 1:
        raise ValueError('Missing or ambiguous camera function')
    symbol = symbols[0]
    if symbol[2] != size or symbol[3] != 0x12 or not symbol[1] & 1:
        raise ValueError('Unexpected camera function symbol')
    if symbol[5] == 0 or symbol[5] >= len(sections):
        raise ValueError('Invalid camera function section')
    section = sections[symbol[5]]
    start = symbol[1] & ~1
    if not section[2] & 4 or start < section[3] or start + size > section[3] + section[5]:
        raise ValueError('Camera function is outside executable code')
    offsets = [segment[1] + start - segment[2] for segment in segments
               if segment[0] == 1 and segment[6] & 1 and start >= segment[2]
               and start + size <= segment[2] + segment[4]]
    if len(offsets) != 1 or offsets[0] != section[4] + start - section[3]:
        raise ValueError('Invalid camera executable segment mapping')
    offset = offsets[0]
    return offset, _range(data, offset, size)


def _camera_callsite(data):
    offset, function = _camera_function(data, _FUNCTION, _FUNCTION_SIZE)
    digest = sha256(function).hexdigest()
    if digest not in (_ORIGINAL_HASH, _PATCHED_HASH):
        raise ValueError('Unsupported camera allocation worker implementation')
    patched = digest == _PATCHED_HASH
    callsite = offset + _CALL_OFFSET
    if _range(data, callsite, 4) != (_NOPS if patched else _CALL):
        raise ValueError('Unexpected camera supplier cleanup instruction')
    return callsite, patched


def _isp_callsite(data):
    offset, function = _camera_function(data, _ISP_FUNCTION, _ISP_FUNCTION_SIZE)
    state = _ISP_HASHES.get(sha256(function).hexdigest())
    if state is None:
        raise ValueError('Unsupported camera ISP allocation implementation')
    for relative, before, after in _ISP_EDITS:
        expected = after if state == 'patched' else before
        if _range(data, offset + relative, len(expected)) != expected:
            raise ValueError('Unexpected high-speed camera geometry instructions')
    return offset + _ISP_OFFSET, state


def _set_isp_geometry(data, callsite, patched):
    offset = callsite - _ISP_OFFSET
    for relative, before, after in _ISP_EDITS:
        value = after if patched else before
        data[offset + relative:offset + relative + len(value)] = value


def fixup_picture_buffers(ctx, file, file_path, fps_fixup, *, tmp_dir=None):
    """Retain live picture buffers and use BDS geometry above 60 fps."""
    if tmp_dir is None:
        raise ValueError('Camera fixup requires a temporary directory')
    path = Path(file_path)
    original = path.read_bytes()
    callsite, patched = _camera_callsite(original)
    isp_site, isp_state = _isp_callsite(original)
    normalized = bytearray(original)
    if patched:
        normalized[callsite:callsite + len(_CALL)] = _CALL
    if isp_state == 'patched':
        _set_isp_geometry(normalized, isp_site, False)

    candidate = Path(tmp_dir) / 'native-camera' / file.basename
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(normalized)
    fps_fixup.run(ctx, file, str(candidate))
    result = bytearray(candidate.read_bytes())
    callsite, patched = _camera_callsite(result)
    isp_site, isp_state = _isp_callsite(result)
    if patched or isp_state != 'fps':
        raise ValueError('FPS fixup produced unexpected camera instructions')
    result[callsite:callsite + len(_NOPS)] = _NOPS
    # Keep the normal/60 fps getters; use BDS dimensions for 120 fps and above.
    _set_isp_geometry(result, isp_site, True)
    _camera_callsite(result)
    _isp_callsite(result)
    if result != original:
        path.write_bytes(result)
