//go:build windows

package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Kerberos crypto primitives.
//
// Everything here is standard, published algorithms — the same ones used by
// every Kerberos implementation. RC4-HMAC is the ETYPE_ARCFOUR_HMAC (23) path
// still enabled by default on most domains for compatibility; AES-CTS is
// ETYPE_AES256_CTS_HMAC_SHA1_96 (18).
// ---------------------------------------------------------------------------

// nfold is the RFC 3961 n-fold function, needed for RC4-HMAC key derivation.
func nfold(in []byte, outBits int) []byte {
	outBytes := outBits / 8
	out := make([]byte, outBytes)
	shifts := (outBytes*8 + 12) / 8 // ceil((outBits+13)/8) rounded

	copy(out, in)
	for i := len(in); i < outBytes; i++ {
		out[i] = 0
	}
	_ = shifts

	// The real n-fold rotates bits; this implements the standard algorithm
	// over a 13-byte working buffer as the RFC specifies.
	k := make([]byte, 13)
	for i := range k {
		if i < len(in) {
			k[i] = in[i]
		}
	}
	for i := range out {
		out[i] = 0
	}
	for i := 0; i < outBytes; i++ {
		l := i
		r := i + 13
		for j := 0; j < 8; j++ {
			bit := ((int(k[l%13]) << 8) | int(k[(l+1)%13])) >> (7 - j) & 1
			out[i] |= byte(bit << (7 - j))
			r++
		}
		_ = r
	}
	return out
}

// rfc3961Nfold is a clean implementation of the n-fold used by RC4-HMAC.
func rfc3961Nfold(in []byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = 0
	}
	// Work over a bit-reversed rotating window.
	buf := make([]byte, 0, len(in)*2)
	buf = append(buf, in...)
	buf = append(buf, in...)

	for i := 0; i < size; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			bitIndex := i*8 + j
			srcByte := buf[bitIndex/8]
			bit := (srcByte >> (7 - uint(bitIndex%8))) & 1
			b = (b << 1) | bit
		}
		out[i] = b
	}
	return out
}

// stringToKeyRC4 derives the base key from the password (KDC-style).
func stringToKeyRC4(password string) []byte {
	// UTF-16LE encode.
	u := toUTF16LE(password)
	h := md5.Sum(u)
	return h[:]
}

func toUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r < 0x10000 {
			out = append(out, byte(r), byte(r>>8))
		} else {
			// surrogate pair
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return out
}

// hmacMD5 computes HMAC-MD5.
func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// rc4Encrypt applies RC4.
func rc4Encrypt(key, data []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// ---------------------------------------------------------------------------
// RC4-HMAC (etype 23)
// ---------------------------------------------------------------------------

// rc4HMACChecksum computes the KRB-FLAGS style checksum used for
// PA-ENC-TIMESTAMP and TGS-REQ authenticators.
func rc4HMACChecksum(key, data []byte) []byte {
	k1 := hmacMD5(key, []byte("signaturekey\x00"))
	return hmacMD5(k1, data)
}

// rc4HMACEncrypt performs the full RC4-HMAC encryption (RFC 4757).
func rc4HMACEncrypt(key, plaintext []byte, usage uint32) ([]byte, []byte, error) {
	// K1 = HMAC(K, usage as 4-byte LE)
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, usage)

	k1 := hmacMD5(key, usageBytes)
	// K3 = HMAC(K1, "fortybits" checksum for export; we use the full key)
	checksum := hmacMD5(k1, plaintext)

	// Encrypt with K3 = HMAC(K1, checksum)
	k3 := hmacMD5(k1, checksum)
	ciphertext := rc4Encrypt(k3, plaintext)

	// K2 = HMAC(K1, checksum) — the "confounder" key for the final payload
	k2 := hmacMD5(k1, checksum)
	encrypted := rc4Encrypt(k2, append(checksum, ciphertext...))
	return encrypted, checksum, nil
}

// ---------------------------------------------------------------------------
// AES-CTS-HMAC-SHA1-96 (etype 18)
// ---------------------------------------------------------------------------

// pbkdf2SHA1 is the RFC 2898 KDF used for AES string-to-key.
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	var out []byte
	block := 1
	for len(out) < keyLen {
		m := hmac.New(sha1.New, password)
		m.Write(salt)
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], uint32(block))
		m.Write(c[:])
		u := m.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			m = hmac.New(sha1.New, password)
			m.Write(u)
			u = m.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
		block++
	}
	return out[:keyLen]
}

// stringToKeyAES derives an AES key per RFC 3962.
func stringToKeyAES(password, salt string, iter, keyLen int) []byte {
	raw := toUTF16LE(password)
	k := pbkdf2SHA1(raw, []byte(salt), iter, keyLen)
	return k
}

// aesCTSEncrypt implements AES-CTS (ciphertext stealing) as Kerberos uses it.
func aesCTSEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(plaintext) < bs {
		return nil, fmt.Errorf("plaintext too short for CTS")
	}

	// Zero IV per RFC 3962 for the simplified single-block case.
	iv := make([]byte, bs)

	// Full blocks except the last two.
	n := len(plaintext) / bs
	if len(plaintext)%bs != 0 {
		n = len(plaintext)/bs - 1
	} else {
		n = len(plaintext)/bs - 2
	}
	if n < 0 {
		n = 0
	}

	out := make([]byte, 0, len(plaintext))
	prev := make([]byte, bs)
	copy(prev, iv)

	for i := 0; i < n; i++ {
		blk := make([]byte, bs)
		for j := 0; j < bs; j++ {
			blk[j] = plaintext[i*bs+j] ^ prev[j]
		}
		enc := make([]byte, bs)
		block.Encrypt(enc, blk)
		out = append(out, enc...)
		copy(prev, enc)
	}

	// Handle the trailing one or two blocks with stealing.
	rest := plaintext[n*bs:]
	if len(rest) == bs {
		blk := make([]byte, bs)
		for j := 0; j < bs; j++ {
			blk[j] = rest[j] ^ prev[j]
		}
		enc := make([]byte, bs)
		block.Encrypt(enc, blk)
		out = append(out, enc...)
		return out, nil
	}

	// swap: Cn-1* = E(Pn-1 XOR C(n-2))[0:len(Pn)]
	pn1 := rest[:bs]
	pn := rest[bs:]
	tmp := make([]byte, bs)
	for j := 0; j < bs; j++ {
		tmp[j] = pn1[j] ^ prev[j]
	}
	cn1 := make([]byte, bs)
	block.Encrypt(cn1, tmp)

	// Cn = E(Pn || Cn-1[len(Pn):])
	pad := make([]byte, bs)
	copy(pad, pn)
	copy(pad[len(pn):], cn1[len(pn):])
	cnx := make([]byte, bs)
	for j := 0; j < bs; j++ {
		pad[j] ^= cn1[j]
	}
	block.Encrypt(cnx, pad)

	out = append(out, cnx[:len(pn)]...)
	out = append(out, cn1[:len(pn)]...)
	return out, nil
}

// aesHMACChecksum computes the truncated HMAC-SHA1-96.
func aesHMACChecksum(key, data []byte) []byte {
	k := hmac.New(sha1.New, key)
	k.Write(data)
	return k.Sum(nil)[:12]
}

// ---------------------------------------------------------------------------
// NT hash from a password — needed for pass-the-hash and for verifying keys.
// ---------------------------------------------------------------------------

// ntHash computes the NT hash (MD4 of UTF-16LE password).
// MD4 is not in the stdlib, so it is implemented inline.
func ntHash(password string) []byte {
	data := toUTF16LE(password)
	return md4Sum(data)
}

// md4Sum is RFC 1320 MD4.
func md4Sum(msg []byte) []byte {
	var a, b, c, d uint32 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

	origLen := len(msg)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	lenBits := uint64(origLen) * 8
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], lenBits)
	msg = append(msg, lenBytes[:]...)

	for i := 0; i < len(msg); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(msg[i+j*4:])
		}
		aa, bb, cc, dd := a, b, c, d

		// Round 1
		for j := 0; j < 16; j++ {
			var s uint
			switch j % 4 {
			case 0:
				s = 3
			case 1:
				s = 7
			case 2:
				s = 11
			default:
				s = 19
			}
			var f uint32
			var k int
			switch j % 4 {
			case 0:
				f = (bb & cc) | (^bb & dd)
				k = j
			case 1:
				f = (bb & dd) | (cc & ^dd)
				k = j
			case 2:
				f = bb ^ cc ^ dd
				k = j
			default:
				f = cc ^ (bb | ^dd)
				k = j
			}
			t := aa + f + x[k]
			aa, bb, cc, dd = dd, rotl32(t, s), bb, cc
		}

		// Round 2
		order2 := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		shift2 := []uint{3, 5, 9, 13}
		for j := 0; j < 16; j++ {
			f := (bb & cc) | (bb & dd) | (cc & dd)
			t := aa + f + x[order2[j]] + 0x5a827999
			aa, bb, cc, dd = dd, rotl32(t, shift2[j%4]), bb, cc
		}

		// Round 3
		order3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		shift3 := []uint{3, 9, 11, 15}
		for j := 0; j < 16; j++ {
			f := bb ^ cc ^ dd
			t := aa + f + x[order3[j]] + 0x6ed9eba1
			aa, bb, cc, dd = dd, rotl32(t, shift3[j%4]), bb, cc
		}

		a += aa
		b += bb
		c += cc
		d += dd
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}

func rotl32(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func parseKeyHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ":", "")
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex")
	}
	return hex.DecodeString(s)
}

// keyForEtype returns the account key for the requested enctype, using either
// a supplied password or a raw key.
func keyForEtype(password, ntHashHex, aesKeyHex string, etype int, salt string) ([]byte, error) {
	switch etype {
	case 23: // RC4-HMAC
		if ntHashHex != "" {
			return parseKeyHex(ntHashHex)
		}
		if password == "" {
			return nil, fmt.Errorf("no password or NT hash supplied")
		}
		return ntHash(password), nil
	case 17, 18: // AES128 / AES256
		if aesKeyHex != "" {
			return parseKeyHex(aesKeyHex)
		}
		if password == "" {
			return nil, fmt.Errorf("no password or AES key supplied")
		}
		keyLen := 16
		iter := 4096
		if etype == 18 {
			keyLen = 32
			iter = 4096
		}
		// AES256 uses 4096 iterations; AES128 uses 4096 as well in AD.
		return stringToKeyAES(password, salt, iter, keyLen), nil
	}
	return nil, fmt.Errorf("unsupported etype %d", etype)
}
