#ifndef SMB2_BYTES_H
#define SMB2_BYTES_H

/**
 *
 * [MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 - 2.2 Message Syntax Unless otherwise specified,
 * multiple-byte fields (16-bit, 32-bit, and 64-bit fields) in an SMB 2 Protocol message MUST be transmitted in
 * little-endian order (least-significant byte first).

 * <strong>network byte order</strong>: The order in which the bytes of a multiple-byte number are transmitted on a
 * network, most significant byte first (in big-endian storage). This may or may not match the order in which numbers

 * To allow machines with different byte order conventions communicate with each other, the Internet protocols specify a canonical
 * byte order convention for data transmitted over the network. This is known as <b>Network Byte Order</b>.
 * <p/>
 * In general, there are two ways to store larger numerical values when stored in memory or when transmitted over digital links:
 * <ul>
 * <li><strong>Little Endian</strong> − In this scheme, low-order byte is stored on the starting address (A) and high-order byte is
 * stored on the next address (A + 1).</li>
 * <li><strong>Big Endian</strong> − In this scheme, high-order byte is stored on the starting address (A) and low-order byte is
 * stored on the next address (A + 1).</li>
 * </ul>
 * For this reason, <b>big-endian</b> byte order is also referred to as <b>network byte order</b>.
 *
 * See <a href="https://en.wikipedia.org/wiki/Endianness">Endianness wikipedia</a>
 * See <a href="http://boostorg.github.io/endian/">Endian Library</a>
 * 综上：
 * Network Byte Order (big-endian) 最高位字节存储在最低地址（按高位优先的顺序存储字），以数组表达的话，大端就是看到的样子，容易阅读。
 * SMB Byte Order (little-endian) 默认的，对于多字节字段，在字节流中，需要知道低位在前高位在后
 */

#include <limits.h>
#include <stdint.h>

 ///////////////////////////////////////////////////////////////////////////////////////////////////
// usage: O32_HOST_ORDER == O32_LITTLE_ENDIAN
//
#if CHAR_BIT != 8
#error "unsupported char size"
#endif

enum
{
	O32_LITTLE_ENDIAN = 0x03020100ul,
	O32_BIG_ENDIAN = 0x00010203ul,
	O32_PDP_ENDIAN = 0x01000302ul,      /* DEC PDP-11 (aka ENDIAN_LITTLE_WORD) */
	O32_HONEYWELL_ENDIAN = 0x02030001ul /* Honeywell 316 (aka ENDIAN_BIG_WORD) */
};

static const union { unsigned char bytes[4]; uint32_t value; } o32_host_order = { { 0, 1, 2, 3 } };

#define O32_HOST_ORDER (o32_host_order.value)
///////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////
//// only tested this on a little endian machine under msvc
//// ENDIAN_ORDER is of multi-character character constants
//// See https://stackoverflow.com/questions/2100331/c-macro-definition-to-determine-big-endian-or-little-endian-machine#9283155
////
//#define LITTLE_ENDIAN 0x41424344UL 
//#define BIG_ENDIAN    0x44434241UL
//#define PDP_ENDIAN    0x42414443UL
//#define ENDIAN_ORDER  ('ABCD') 
//
//#if ENDIAN_ORDER==LITTLE_ENDIAN
//#error "machine is little endian"
//#elif ENDIAN_ORDER==BIG_ENDIAN
//#error "machine is big endian"
//#elif ENDIAN_ORDER==PDP_ENDIAN
//#error "jeez, machine is PDP!"
//#else
//#error "What kind of hardware is this?!"
//#endif
/////////////////////////////////////////////////////////////




#if __STDC_VERSION__ >= 199901L
# define IS_LITTLE_ENDIAN (1 == *(unsigned char *)&(const int){1})
#endif

//////////////////////////////// BGN of manipulating byte buffer in little endian 

#if IS_LITTLE_ENDIAN || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

#define _IS_LITTLE_ENDIAN

#define BYTES_GET_U1(buffer, offset)                  *((const uint8_t *)buffer + offset)
// read 2 bytes as a uint16_t from the buffer (unsigned version of BYTES_GET_2)
#define BYTES_GET_U2(buffer, offset) *(const uint16_t*)((const uint8_t *)buffer + offset)
// read 4 bytes as a uint32_t from the buffer (unsigned version of BYTES_GET_4)
#define BYTES_GET_U4(buffer, offset) *(const uint32_t*)((const uint8_t *)buffer + offset)
// read 8 bytes as a uint64_t from the buffer (unsigned version of BYTES_GET_8)
#define BYTES_GET_U8(buffer, offset) *(const uint64_t*)((const uint8_t *)buffer + offset)

#define BYTES_GET_U1_NC(buffer, offset)           *((int8_t *)buffer + offset)
#define BYTES_GET_U2_NC(buffer, offset) *(int16_t*)((int8_t *)buffer + offset)
#define BYTES_GET_U4_NC(buffer, offset) *(int32_t*)((int8_t *)buffer + offset)
#define BYTES_GET_U8_NC(buffer, offset) *(int64_t*)((int8_t *)buffer + offset)

#define BYTES_GET_1(buffer, offset)                 *((const int8_t *)buffer + offset)
#define BYTES_GET_2(buffer, offset) *(const int16_t*)((const int8_t *)buffer + offset)
#define BYTES_GET_4(buffer, offset) *(const int32_t*)((const int8_t *)buffer + offset)
#define BYTES_GET_8(buffer, offset) *(const int64_t*)((const int8_t *)buffer + offset)

#define BYTES_GET_1_NC(buffer, offset)           *((int8_t *)buffer + offset)
#define BYTES_GET_2_NC(buffer, offset) *(int16_t*)((int8_t *)buffer + offset)
#define BYTES_GET_4_NC(buffer, offset) *(int32_t*)((int8_t *)buffer + offset)
#define BYTES_GET_8_NC(buffer, offset) *(int64_t*)((int8_t *)buffer + offset)

// write a uint8_t (1 bytes) to the buffer
#define BYTES_SET_U1(buffer, offset, value)            *((uint8_t *)buffer + offset) = value;
// write a uint16_t (2 bytes) to the buffer
#define BYTES_SET_U2(buffer, offset, value) *(uint16_t*)((uint8_t *)buffer + offset) = value;
// write a uint32_t (4 bytes) to the buffer
#define BYTES_SET_U4(buffer, offset, value) *(uint32_t*)((uint8_t *)buffer + offset) = value;
// write a uint64_t (8 bytes) to the buffer
#define BYTES_SET_U8(buffer, offset, value) *(uint64_t*)((uint8_t *)buffer + offset) = value;

// write a int8_t (1 bytes) to the buffer
#define BYTES_SET_1(buffer, offset, value)            *((uint8_t *)buffer + offset) = value;
// write a int16_t (2 bytes) to the buffer
#define BYTES_SET_2(buffer, offset, value) *(uint16_t*)((uint8_t *)buffer + offset) = value;
// write a int32_t (4 bytes) to the buffer
#define BYTES_SET_4(buffer, offset, value) *(uint32_t*)((uint8_t *)buffer + offset) = value;
// write a int64_t (8 bytes) to the buffer
#define BYTES_SET_8(buffer, offset, value) *(uint64_t*)((uint8_t *)buffer + offset) = value;

#else

// read a byte as a uint8_t from the buffer
#define BYTES_GET_U1(buffer, offset) ((unsigned int)(((const uint8_t *)(buffer))[offset]))
// read 1 byte as a int8_t from the buffer (signed version of BYTES_GET_1)
#define BYTES_GET_1(buffer, offset) ((int8_t)BYTES_GET_U1(buffer, offset))

#define BYTES_GET_1_(buffer, offset) ((unsigned int)BYTES_GET_U1(buffer, offset))
#define BYTES_GET_1_NC(buffer, offset) (((int8_t *)(buffer))[offset]) /* Non-const version of BYTES_GET_1 */

// read 2 bytes as a int16_t from the buffer
#define BYTES_GET_2(buffer, offset) (BYTES_GET_1_(buffer, offset) | BYTES_GET_1_(buffer, (offset) + 1) << 8)
// read 4 bytes as a int32_t from the buffer
#define BYTES_GET_4(buffer, offset) (BYTES_GET_2(buffer, offset) | BYTES_GET_2(buffer, (offset) + 2) << 16)
// read 8 bytes as a int64_t from the buffer (you should use an 64 bit integer to store it)
#define BYTES_GET_8(ptr, ofs) (BYTES_GET_4(ptr, ofs) | (((int64_t)BYTES_GET_4(ptr, (ofs) + 4)) << 32))

// write a int16_t (2 bytes) to the buffer.
#define BYTES_SET_2(buffer, offset, value) (BYTES_GET_1_NC(buffer, offset) = (int8_t)((value) & 0xFF), BYTES_GET_1_NC(buffer, (offset) + 1) = (int8_t)((value) >> 8))
// write a int32_t (4 bytes) to the buffer.
#define BYTES_SET_4(buffer, offset, value) (BYTES_SET_2(buffer, offset, value & 0xFFFF), BYTES_SET_2(buffer, offset + 2, value >> 16))
//// write a int64_t (8 bytes) to the buffer.
//#define BYTES_SET_8(buffer, offset, value)

// read 2 bytes as a uint16_t from the buffer (unsigned version of BYTES_GET_2)
#define BYTES_GET_U2(buffer, offset) ((uint16_t)BYTES_GET_2(buffer, offset))
// read 4 bytes as a uint32_t from the buffer (unsigned version of BYTES_GET_4)
#define BYTES_GET_U4(buffer, offset) ((uint32_t)BYTES_GET_4(buffer, offset))
// read 8 bytes as a uint64_t from the buffer (unsigned version of BYTES_GET_8)
#define BYTES_GET_U8(buffer, offset) ((uint64_t)BYTES_GET_8(buffer, offset))

// write a uint16_t (2 bytes) to the buffer (unsigned version of BYTES_SET_2)
#define BYTES_SET_U2(buffer, offset, value) BYTES_SET_2((buffer), (offset), ((int16_t)(value)))
// write a uint32_t (4 bytes) to the buffer (unsigned version of BYTES_SET_4)
#define BYTES_SET_U4(buffer, offset, value) BYTES_SET_4((buffer), (offset), ((int32_t)(value)))
//// write a uint64_t (8 bytes) to the buffer (unsigned version of BYTES_SET_4)
//#define BYTES_SET_U8(buffer, offset, value) BYTES_SET_8((buffer), (offset), ((int64_t)(value)))

#endif

////////////////////////// END of manipulating byte buffer in little endian 


////////////////////////////////

// read 2 bytes as an uint16_t in little endian (unsafe, unchecking the buffer's boundary)
inline uint16_t bytes_to_uint16_le(const void *buffer)
{
	static unsigned long signature = 0x01020304UL;
	if (1 == (unsigned char&)signature) // big endian
	{
		return BYTES_GET_U2(buffer, 0);
	}
	if (2 == (unsigned char&)signature) // the PDP style
	{
		// fall through
	}
	if (4 == (unsigned char&)signature) // little endian
	{
		// fall through
	}
	// only weird machines get here
	return *(uint16_t*)(buffer); // ?
}

// read 4 bytes as an uint32_t in little endian (unsafe, unchecking the buffer's boundary)
inline uint32_t bytes_to_uint32_le(const void *buffer)
{
	static unsigned long signature = 0x01020304UL;
	if (1 == (unsigned char&)signature) // big endian
	{
		return BYTES_GET_U4(buffer, 0);
	}
	if (2 == (unsigned char&)signature) // the PDP style
	{
		// fall through
	}
	if (4 == (unsigned char&)signature) // little endian
	{
		// fall through
	}
	// only weird machines get here
	return *(uint32_t*)(buffer); // ?
}

// read 4 bytes as an uint32_t in little endian (unsafe, unchecking the buffer's boundary)
inline uint64_t bytes_to_uint64_le(const void *buffer)
{
	static unsigned long signature = 0x01020304UL;
	if (1 == (unsigned char&)signature) // big endian
	{
		return BYTES_GET_U8(buffer, 0);
	}
	if (2 == (unsigned char&)signature) // the PDP style
	{
		// fall through
	}
	if (4 == (unsigned char&)signature) // little endian
	{
		// fall through
	}
	// only weird machines get here
	return *(uint64_t*)(buffer); // ?
}
/////////////////////////////////

#endif 