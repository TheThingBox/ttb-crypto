package ttb_crypto

import (
  "crypto/aes"
  "crypto/cipher"
  "encoding/hex"
  "fmt"
  "strings"
)

type AES_GCM interface {
  cypher(data string) (string, error)
  uncypher(data string) (string, error)
}

type aes_gcm struct {
  key  []byte
  iv   []byte
}

func loadAesGcm(key string, iv string) AES_GCM {
    var t AES_GCM
    k, _ := hex.DecodeString(key)
    i, _ := hex.DecodeString(iv)
    t = &aes_gcm{k, i}
    return t
}

func genAesGcmKeys() (key string, iv string, err error) {
  rep, err := run("openssl enc -aes256 -k secret -P -md sha1")
  if err != nil {
     return
  }
  repSlice := clearStringArray(strings.Split(rep, "\n"))

  for index := 0; index < len(repSlice); index++ {
    i:= clearStringArray(strings.Split(repSlice[index], "="))
    if len(i) == 2 {
      if i[0] == "key" {
        key = i[1]
      } else if i[0] == "iv" {
        iv = i[1]
      }
    }
  }
  return
}

func (g *aes_gcm) cypher(data string) (string, error) {
  block, err := aes.NewCipher(g.key)
  if err != nil {
    return "", err
  }

  aesgcm, err := cipher.NewGCM(block)
  if err != nil {
    return "", err
  }

  ciphertext := aesgcm.Seal(nil, g.iv[:12], []byte(data), nil)
  return fmt.Sprintf("%x",ciphertext), nil
}

func (g *aes_gcm) uncypher(data string) (string, error) {
  block, err := aes.NewCipher(g.key)
  if err != nil {
    return "", err
  }

  aesgcm, err := cipher.NewGCM(block)
  if err != nil {
    return "", err
  }

  ciphertext, _ := hex.DecodeString(data)

  plaintext, err := aesgcm.Open(nil, g.iv[:12], ciphertext, nil)
  if err != nil {
    return "", err
  }

  return string(plaintext), nil
}
