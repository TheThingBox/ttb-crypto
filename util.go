package ttb_crypto

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

func encodeBase64(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}

func parseInt(t string, base int) int {
	i, _ := strconv.ParseInt(t, base, 32)
	return int(i)
}

func indexString(vs []string, t string) int {
	for i, v := range vs {
		if v == t {
			return i
		}
	}
	return -1
}

func clearStringArray(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, strings.Trim(str, " "))
		}
	}
	return r
}

func parseSlice(sl string) (int, int) {
	if strings.HasPrefix(sl, MSG_PREFFIX) == false {
		return -1, -1
	}
	lenPre := len(MSG_PREFFIX)
	lenSl := len(sl)
	if lenSl < lenPre+MSG_SIZE_BYTES {
		return -1, -1
	}
	i := parseInt(sl[lenPre:lenPre+MSG_SIZE_BYTES], 16)

	if lenSl < lenPre+MSG_SIZE_BYTES+i {
		return -1, -1
	}

	s := parseInt(sl[lenPre+MSG_SIZE_BYTES:lenPre+MSG_SIZE_BYTES+i], 16)

	if lenSl < lenPre+MSG_SIZE_BYTES+i+s {
		return -1, -1
	}

	return (lenPre + MSG_SIZE_BYTES + i), (lenPre + MSG_SIZE_BYTES + i + s)
}

func createSlice(w string) string {
	var m bytes.Buffer
	m.WriteString(MSG_PREFFIX)
	lenWord := strconv.FormatInt(int64(len(w)), 16)
	lenLen := strconv.FormatInt(int64(len(lenWord)), 16)
	if len(lenLen) > MSG_SIZE_BYTES {
		return ""
	} else if len(lenLen) == 1 {
		m.WriteString("0")
	}
	m.WriteString(lenLen)
	m.WriteString(lenWord)
	m.WriteString(w)

	return m.String()
}

func hashSha1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
}
