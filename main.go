package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func prefix0(s string) string {
	if len(s) < 6 {
		return strings.Repeat("0", 6-len(s)) + s
	}
	return s
}

func hmacs(secret string, interval int64) string {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return err.Error()
	}
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	hashs := hmac.New(sha1.New, key)
	hashs.Write(bs)
	h := hashs.Sum(nil)
	o := (h[19] & 15)

	var header uint32
	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)

	if err != nil {
		fmt.Println(err)
	}

	h12 := (int(header) & 0x7fffffff) % 1000000
	otp := strconv.Itoa(int(h12))
	return prefix0(otp)
}

func getTOTPToken(secret string) string {
	interval := time.Now().Unix() / 30
	fmt.Println("Time Now ", interval)
	return hmacs(secret, interval)
}

func main() {
	fmt.Println("YOU Token is :", getTOTPToken("YOUR TOKEN HERE"))
}
