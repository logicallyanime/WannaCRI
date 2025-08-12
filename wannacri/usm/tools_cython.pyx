# cython: boundscheck=False, wraparound=False, cdivision=True
import math
import threading
import unicodedata
import re
from typing import Tuple, IO, List, Callable, Union

# ------------------------------
# Slugify (unchanged)
# ------------------------------
cpdef str slugify(value, bint allow_unicode=True):
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize("NFKC", value)
    else:
        value = (
            unicodedata.normalize("NFKD", value)
            .encode("ascii", "ignore")
            .decode("ascii")
        )
    value = re.sub(r"[^\w\s.,+-]", "", value.lower())
    return re.sub(r"[-\s]+", "-", value).strip("-_")


# ------------------------------
# Chunk validation
# ------------------------------
cpdef bint is_valid_chunk(bytes signature):
    if len(signature) < 4:
        return False
    return signature[:4] in (b"CRID", b"@SFV", b"@SFA", b"@ALP")


cpdef bint is_payload_list_pages(bytes payload):
    if len(payload) < 4:
        return False
    return payload[:4] == b"@UTF"


# ------------------------------
# Chunk size and padding
# ------------------------------
cpdef tuple chunk_size_and_padding(object header):
    # Ensure we have a bytes-like object
    if not isinstance(header, (bytes, bytearray)):
        raise TypeError("header must be bytes or bytearray")

    # Make a writable copy if needed
    cdef bytearray header_buf = bytearray(header)

    cdef int size = int.from_bytes(header_buf[4:8], "big")
    cdef int offset = header_buf[9]
    cdef int padding_size = int.from_bytes(header_buf[10:12], "big")

    size -= offset + padding_size
    if size < 0:
        raise ValueError("Negative size")

    return size, padding_size


# ------------------------------
# Key generation (memoryview)
# ------------------------------
cpdef Tuple[bytes, bytes] generate_keys(unsigned long long key_num):
    cdef bytes cipher_key_bytes = key_num.to_bytes(8, "little")
    cdef unsigned char[:] cipher_key = cipher_key_bytes
    cdef unsigned char[0x20] key
    cdef int i

    key[0x00] = cipher_key[0]
    key[0x01] = cipher_key[1]
    key[0x02] = cipher_key[2]
    key[0x03] = (cipher_key[3] - 0x34) & 0xFF
    key[0x04] = (cipher_key[4] + 0xF9) & 0xFF
    key[0x05] = cipher_key[5] ^ 0x13
    key[0x06] = (cipher_key[6] + 0x61) & 0xFF
    key[0x07] = key[0x00] ^ 0xFF
    key[0x08] = (key[0x01] + key[0x02]) & 0xFF
    key[0x09] = (key[0x01] - key[0x07]) & 0xFF
    key[0x0A] = key[0x02] ^ 0xFF
    key[0x0B] = key[0x01] ^ 0xFF
    key[0x0C] = (key[0x0B] + key[0x09]) & 0xFF
    key[0x0D] = (key[0x08] - key[0x03]) & 0xFF
    key[0x0E] = key[0x0D] ^ 0xFF
    key[0x0F] = (key[0x0A] - key[0x0B]) & 0xFF
    key[0x10] = (key[0x08] - key[0x0F]) & 0xFF
    key[0x11] = key[0x10] ^ key[0x07]
    key[0x12] = key[0x0F] ^ 0xFF
    key[0x13] = key[0x03] ^ 0x10
    key[0x14] = (key[0x04] - 0x32) & 0xFF
    key[0x15] = (key[0x05] + 0xED) & 0xFF
    key[0x16] = key[0x06] ^ 0xF3
    key[0x17] = (key[0x13] - key[0x0F]) & 0xFF
    key[0x18] = (key[0x15] + key[0x07]) & 0xFF
    key[0x19] = (0x21 - key[0x13]) & 0xFF
    key[0x1A] = key[0x14] ^ key[0x17]
    key[0x1B] = (key[0x16] + key[0x16]) & 0xFF
    key[0x1C] = (key[0x17] + 0x44) & 0xFF
    key[0x1D] = (key[0x03] + key[0x04]) & 0xFF
    key[0x1E] = (key[0x05] - key[0x16]) & 0xFF
    key[0x1F] = key[0x1D] ^ key[0x13]

    cdef unsigned char[0x40] video_key
    cdef unsigned char[0x20] audio_key
    cdef bytes audio_t = b"URUC"
    cdef unsigned char[:] audio_t_view = audio_t

    for i in range(0x20):
        video_key[i] = key[i]
        video_key[0x20 + i] = key[i] ^ 0xFF
        if i % 2 != 0:
            audio_key[i] = audio_t_view[(i >> 1) % 4]
        else:
            audio_key[i] = key[i] ^ 0xFF

    return bytes(video_key), bytes(audio_key)


# ------------------------------
# Video decryption (memoryview)
# ------------------------------
cpdef bytes decrypt_video_packet(bytes packet, bytes video_key):
    if len(video_key) < 0x40:
        raise ValueError(
            f"Video key should be 0x40 bytes long. Given {len(video_key)}"
        )

    # Step 1: Make a writable copy
    cdef bytearray data_buf = bytearray(packet)

    # Step 2: Take memoryview from the variable, not from a function call
    cdef unsigned char[:] data_view = data_buf
    cdef const unsigned char[:] vkey_view = video_key  # read-only view

    cdef unsigned char[0x40] rolling
    cdef int i, encrypted_part_size

    encrypted_part_size = len(data_view) - 0x40
    if encrypted_part_size >= 0x200:
        for i in range(0x40):
            rolling[i] = vkey_view[i]

        for i in range(0x100, encrypted_part_size):
            data_view[0x40 + i] ^= rolling[0x20 + (i % 0x20)]
            rolling[0x20 + (i % 0x20)] = (
                data_view[0x40 + i] ^ vkey_view[0x20 + (i % 0x20)]
            )

        for i in range(0x100):
            rolling[i % 0x20] ^= data_view[0x140 + i]
            data_view[0x40 + i] ^= rolling[i % 0x20]

    return bytes(data_buf)


# ------------------------------
# Video encryption (memoryview)
# ------------------------------
cpdef bytes encrypt_video_packet(bytes packet, bytes video_key):
    if len(video_key) < 0x40:
        raise ValueError(
            f"Video key should be 0x40 bytes long. Given {len(video_key)}"
        )

    cdef bytearray data_buf = bytearray(packet)
    cdef unsigned char[:] data_view = data_buf
    cdef const unsigned char[:] vkey_view = video_key

    cdef unsigned char[0x40] rolling
    cdef int i, encrypted_part_size, plainbyte

    if len(data_view) >= 0x240:
        encrypted_part_size = len(data_view) - 0x40
        for i in range(0x40):
            rolling[i] = vkey_view[i]

        for i in range(0x100):
            rolling[i % 0x20] ^= data_view[0x140 + i]
            data_view[0x40 + i] ^= rolling[i % 0x20]

        for i in range(0x100, encrypted_part_size):
            plainbyte = data_view[0x40 + i]
            data_view[0x40 + i] ^= rolling[0x20 + (i % 0x20)]
            rolling[0x20 + (i % 0x20)] = (
                plainbyte ^ vkey_view[0x20 + (i % 0x20)]
            )

    return bytes(data_buf)


# ------------------------------
# Audio encryption/decryption (memoryview)
# ------------------------------
cdef bytes _crypt_audio_packet(bytes packet, bytes key):
    cdef bytearray data_buf = bytearray(packet)
    cdef unsigned char[:] data_view = data_buf
    cdef const unsigned char[:] key_view = key
    cdef int i

    if len(data_view) > 0x140:
        for i in range(0x140, len(data_view)):
            data_view[i] ^= key_view[i % 0x20]

    return bytes(data_buf)

cpdef bytes encrypt_audio_packet(bytes packet, bytes key):
    return _crypt_audio_packet(packet, key)

cpdef bytes decrypt_audio_packet(bytes packet, bytes key):
    return _crypt_audio_packet(packet, key)


# ------------------------------
# Misc helpers (fixed for Cython)
# ------------------------------

# Can't use Callable or closures in cpdef, so we just return a Python function
def pad_to_next_sector(position: int):
    """Return a function that calculates padding to the next 0x800 sector."""
    def pad(chunk_size: int) -> int:
        unpadded_position = position + chunk_size
        multiple = math.ceil(unpadded_position / 0x800)
        return 0x800 * multiple - unpadded_position
    return pad


cpdef int get_video_header_end_offset(int num_keyframes):
    cdef int seek_info_offset = 0xA40
    cdef int seek_info_headers_size = 0x40
    cdef int strings_size = 0x38
    cdef int s_array_size = 1 * 4 + 4 * 4 + 2 + 2
    cdef int d_array_size = num_keyframes * 8 + num_keyframes * 4
    cdef int total_size = (
        seek_info_offset
        + seek_info_headers_size
        + s_array_size
        + d_array_size
        + strings_size
    )
    cdef int padding = 0x80 - (total_size % 0x80)
    return total_size + padding


cpdef str bytes_to_hex(bytes data):
    return " ".join([f"{k:02x}" for k in data])


cpdef bint is_usm(bytes magic):
    if len(magic) < 4:
        return False
    return magic[:4] == b"CRID"


# ------------------------------
# Generators (fixed for Cython)
# ------------------------------

# Remove IO and threading.Lock type hints — just use object
def video_sink(usmfile, usmmutex, offsets_and_sizes, keyframes):
    """Yield (frame, is_keyframe) tuples from a USM file."""
    num_frames = len(offsets_and_sizes)
    keyframe_set = set(keyframes)  # O(1) lookup instead of O(n)
    for i in range(num_frames):
        offset, size = offsets_and_sizes[i]
        is_keyframe = i in keyframe_set
        with usmmutex:
            usmfile.seek(offset)
            frame = usmfile.read(size)
        yield frame, is_keyframe


def audio_sink(usmfile, usmmutex, offsets_and_sizes):
    """Yield audio frames from a USM file."""
    num_frames = len(offsets_and_sizes)
    for i in range(num_frames):
        offset, size = offsets_and_sizes[i]
        with usmmutex:
            usmfile.seek(offset)
            frame = usmfile.read(size)
        yield frame