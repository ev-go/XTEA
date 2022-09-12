package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func rol(base uint32, shift uint32) uint32 {
	var res uint32
	shift &= 0x1F
	res = (base << shift) | (base >> (32 - shift))
	return res
}

func main() {
	original := []byte{0x02, 0x00, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0xCB, 0xDE, 0xC1, 0xCE, 0xC9, 0x5F, 0xD2, 0xC5, 0xCA, 0xD1, 0xD2, 0x00, 0x01, 0x00, 0x02, 0x00, 0x46, 0x53, 0x4C, 0x49, 0x53, 0x54, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x72, 0x75, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x80, 0x00, 0x00, 0x21, 0x00, 0x06, 0x00, 0x01, 0x80, 0x00, 0xC0, 0x01, 0xC0, 0x02, 0xC0, 0x03, 0xC0, 0xCE, 0x40, 0x00, 0x00, 0x00, 0x00}

	testKey := []byte{0xA1, 0x2B, 0xC3, 0x47, 0x65, 0x64, 0x56, 0x58, 0x51, 0x03, 0x03, 0x01, 0x05, 0x16, 0x07, 0xD8, 0x1F, 0x52, 0x33, 0x4A, 0x5A, 0x63, 0x79, 0x3E, 0x54, 0x76, 0x13, 0x54, 0x45, 0x36, 0x27, 0x28}

	block := make([]byte, 16)
	for i := 0; i < len(original)/16; i++ {
		block = crypt(testKey, original[(i*16):((i+1)*16)], 32)
		fmt.Println(hex.Dump(block))
	}
}

func crypt(testKey []byte, block []byte, rounds uint32) []byte {
	var a, b, c, d, sum, t uint32
	var buf [4]uint32 //Буфер нужен чтобы обойти баг с невыровнянным plain,
	var key [8]uint32

	key[0] = binary.LittleEndian.Uint32(testKey[:4])
	key[1] = binary.LittleEndian.Uint32(testKey[4:8])
	key[2] = binary.LittleEndian.Uint32(testKey[8:12])
	key[3] = binary.LittleEndian.Uint32(testKey[12:16])
	key[4] = binary.LittleEndian.Uint32(testKey[16:20])
	key[5] = binary.LittleEndian.Uint32(testKey[20:24])
	key[6] = binary.LittleEndian.Uint32(testKey[24:28])
	key[7] = binary.LittleEndian.Uint32(testKey[28:32])

	buf[0] = binary.LittleEndian.Uint32(block[:4])
	buf[1] = binary.LittleEndian.Uint32(block[4:8])
	buf[2] = binary.LittleEndian.Uint32(block[8:12])
	buf[3] = binary.LittleEndian.Uint32(block[12:16])

	sum = 0
	a = buf[0] + key[0]
	b = buf[1] + key[1]
	c = buf[2] + key[2]
	d = buf[3] + key[3]
	for i := 0; i != int(rounds); i++ {
		a = a + (((b << 4) + rol(key[(sum%4)+4], b)) ^ (d + sum) ^ ((b >> 5) + rol(key[sum%4], b>>27)))
		sum = sum + 0x9E3779B9
		c = c + (((d << 4) + rol(key[((sum>>11)%4)+4], d)) ^ (b + sum) ^ ((d >> 5) + rol(key[(sum>>11)%4], d>>27)))

		t = a
		a = b
		b = c
		c = d
		d = t
	}

	buf[0] = a ^ key[4]
	buf[1] = b ^ key[5]
	buf[2] = c ^ key[6]
	buf[3] = d ^ key[7]
	end := make([]byte, 16)

	binary.LittleEndian.PutUint32(end[:4], buf[0])
	binary.LittleEndian.PutUint32(end[4:8], buf[1])
	binary.LittleEndian.PutUint32(end[8:12], buf[2])
	binary.LittleEndian.PutUint32(end[12:16], buf[3])

	return end
}

func decrypt(testKey []byte, block []byte, rounds uint32) []byte {
	var buf [4]uint32
	var a, b, c, d, delta, sum, t uint32
	var key [8]uint32

	key[0] = binary.LittleEndian.Uint32(testKey[:4])
	key[1] = binary.LittleEndian.Uint32(testKey[4:8])
	key[2] = binary.LittleEndian.Uint32(testKey[8:12])
	key[3] = binary.LittleEndian.Uint32(testKey[12:16])
	key[4] = binary.LittleEndian.Uint32(testKey[16:20])
	key[5] = binary.LittleEndian.Uint32(testKey[20:24])
	key[6] = binary.LittleEndian.Uint32(testKey[24:28])
	key[7] = binary.LittleEndian.Uint32(testKey[28:32])

	buf[0] = binary.LittleEndian.Uint32(block[:4])
	buf[1] = binary.LittleEndian.Uint32(block[4:8])
	buf[2] = binary.LittleEndian.Uint32(block[8:12])
	buf[3] = binary.LittleEndian.Uint32(block[12:16])

	delta = binary.LittleEndian.Uint32([]byte{0xb9, 0x79, 0x37, 0x9e})
	sum = delta * rounds // & mask

	d = buf[3] ^ key[7]
	c = buf[2] ^ key[6]
	b = buf[1] ^ key[5]
	a = buf[0] ^ key[4]

	for i := int(rounds) - 1; i != -1; i-- {
		t = d
		d = c
		c = b
		b = a
		a = t

		c = c - (((d << 4) + rol(key[((sum>>11)%4)+4], d)) ^ (b + sum) ^ ((d >> 5) + rol(key[(sum>>11)%4], d>>27)))

		sum = sum - 0x9E3779B9

		a = a - (((b << 4) + rol(key[(sum%4)+4], b)) ^ (d + sum) ^ ((b >> 5) + rol(key[sum%4], b>>27)))
	}

	buf[3] = d - key[3]
	buf[2] = c - key[2]
	buf[1] = b - key[1]
	buf[0] = a - key[0]

	end := make([]byte, 16)

	binary.LittleEndian.PutUint32(end[:4], buf[0])
	binary.LittleEndian.PutUint32(end[4:8], buf[1])
	binary.LittleEndian.PutUint32(end[8:12], buf[2])
	binary.LittleEndian.PutUint32(end[12:16], buf[3])

	return end
}
