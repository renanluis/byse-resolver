"""Byse proof of work using uint32 arithmetic and native memory in the hot loop."""

from libc.stdint cimport uint32_t, uint64_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy


cdef inline uint32_t rotate(uint32_t value, unsigned int bits) noexcept nogil:
    return (value << bits) | (value >> (32 - bits))


cdef inline void mix(uint32_t* state) noexcept nogil:
    cdef uint32_t a = state[0], b = state[1], c = state[2], d = state[3]
    a += b
    d = rotate(d ^ a, 16)
    c += d
    b = rotate(b ^ c, 12)
    a += b
    d = rotate(d ^ a, 8)
    c += d
    b = rotate(b ^ c, 7)
    state[0], state[1], state[2], state[3] = a, b, c, d


cdef void hash_words(const unsigned char* data, Py_ssize_t length, uint32_t* output) noexcept nogil:
    cdef uint32_t state[4]
    cdef uint32_t scratch[512]
    cdef uint32_t word, value
    cdef uint32_t golden = 2654435761
    cdef uint32_t prime = 2246822519
    cdef Py_ssize_t pos
    cdef int index, iteration, item
    state[0], state[1], state[2], state[3] = 1779033703, 3144134277, 1013904242, 2773480762
    for pos in range(length):
        state[0] = rotate(state[0] + data[pos], 7)
        mix(state)
    for iteration in range(8):
        mix(state)
    for index in range(512):
        mix(state)
        scratch[index] = state[0] ^ state[2]
    for iteration in range(2):
        for index in range(512):
            word = scratch[index]
            value = rotate(word + scratch[word & 511], 13)
            value ^= scratch[(index + 1) & 511] * golden
            scratch[index] = value
            state[0] ^= value
            mix(state)
    for index in range(8):
        mix(state)
        word = state[0]
        for item in range(index * 64, (index + 1) * 64):
            word = rotate(word + scratch[item], 5) ^ (scratch[item] * prime)
        output[index] = word ^ state[2]


def digest(bytes data):
    """Expose the eight digest words for correctness checks."""
    cdef uint32_t words[8]
    cdef const unsigned char* raw = data
    cdef Py_ssize_t size = len(data)
    with nogil:
        hash_words(raw, size, words)
    return (words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7])


def search(bytes prefix, unsigned int difficulty, uint64_t start, unsigned int count):
    """Search a finite batch; the caller checks the deadline between batches."""
    if difficulty > 32:
        raise ValueError("Byse: invalid native difficulty")
    if count == 0:
        return None
    if start > <uint64_t>-1 - (count - 1):
        raise OverflowError("Byse: invalid candidate range")
    cdef Py_ssize_t length = len(prefix)
    cdef const unsigned char* raw = prefix
    cdef unsigned char* buffer = <unsigned char*>malloc(length + 20)
    if buffer == NULL:
        raise MemoryError()
    cdef unsigned char digits[20]
    cdef uint32_t words[8]
    cdef uint64_t candidate, value
    cdef unsigned int offset
    cdef int used, index
    cdef bint found = False
    try:
        with nogil:
            memcpy(buffer, raw, length)
            for offset in range(count):
                candidate = start + offset
                value = candidate
                used = 0
                while True:
                    digits[used] = 48 + value % 10
                    used += 1
                    value = value // 10
                    if value == 0:
                        break
                for index in range(used):
                    buffer[length + index] = digits[used - index - 1]
                hash_words(buffer, length + used, words)
                if difficulty == 0 or words[0] >> (32 - difficulty) == 0:
                    found = True
                    break
        return str(candidate) if found else None
    finally:
        free(buffer)
