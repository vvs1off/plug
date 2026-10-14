//go:build windows

package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"time"
)

// rc4HMACChecksumLocal mirrors the Kerberos KRB-FLAGS checksum used with RC4
// session keys.
func rc4HMACChecksumLocal(key, data []byte) []byte {
	k1 := hmacMD5Local(key, []byte("signaturekey\x00"))
	return hmacMD5Local(k1, data)
}

func hmacMD5Local(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func rc4Stream(key, data []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return data
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

func nowUTC() time.Time { return time.Now().UTC() }

// derTime encodes a KerberosTime (GeneralizedTime, Z-suffixed).
func derTime(t time.Time) []byte {
	return derTag(0x18, []byte(t.UTC().Format("20060102150405Z")))
}
