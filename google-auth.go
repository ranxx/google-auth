package googleauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	shifts = []uint16{56, 48, 40, 32, 24, 16, 8, 0}
)

// GoogleAuth ...
type GoogleAuth struct {
}

func NewGoogleAuth() *GoogleAuth {
	// NewGoogleAuth new
	return &GoogleAuth{}
}

func (g *GoogleAuth) un() int64 {
	return time.Now().UnixNano() / 1000 / 30
}

func (g *GoogleAuth) hmacSha1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	if total := len(data); total > 0 {
		h.Write(data)
	}
	return h.Sum(nil)
}

func (g *GoogleAuth) base32encode(src []byte) string {
	return base32.StdEncoding.EncodeToString(src)
}

func (g *GoogleAuth) base32decode(s string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(s)
}

func (g *GoogleAuth) toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func (g *GoogleAuth) toUint32(bts []byte) uint32 {
	return (uint32(bts[0]) << 24) + (uint32(bts[1]) << 16) +
		(uint32(bts[2]) << 8) + uint32(bts[3])
}

func (g *GoogleAuth) oneTimePassword(key []byte, data []byte) uint32 {
	hash := g.hmacSha1(key, data)
	offset := hash[len(hash)-1] & 0x0F
	hashParts := hash[offset : offset+4]
	hashParts[0] = hashParts[0] & 0x7F
	number := g.toUint32(hashParts)
	return number % 1000000
}

// GetSecret 获取秘钥
func (g *GoogleAuth) GetSecret() string {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, g.un())
	return strings.ToUpper(g.base32encode(g.hmacSha1(buf.Bytes(), nil)))
}

// GetCode 获取动态码
func (g *GoogleAuth) GetCode(secret string) (string, error) {
	secretUpper := strings.ToUpper(secret)
	secretKey, err := g.base32decode(secretUpper)
	if err != nil {
		return "", err
	}
	number := g.oneTimePassword(secretKey, g.toBytes(time.Now().Unix()/30))
	return fmt.Sprintf("%06d", number), nil
}

// GetQrcode 获取动态码二维码内容
func (g *GoogleAuth) GetQrcode(user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s?secret=%s", user, secret)
}

// GetQrcodeUrl 获取动态码二维码图片地址,这里是第三方二维码api
func (g *GoogleAuth) GetQrcodeUrl(user, secret string) string {
	qrcode := g.GetQrcode(user, secret)
	width := "200"
	height := "200"
	data := url.Values{}
	data.Set("data", qrcode)
	return "https://api.qrserver.com/v1/create-qr-code/?" + data.Encode() + "&size=" + width + "x" + height + "&ecc=M"
}

// VerifyCode 验证动态码
func (g *GoogleAuth) VerifyCode(secret, code string) (bool, error) {
	_code, err := g.GetCode(secret)
	if err != nil {
		return false, err
	}
	return _code == code, nil
}
