package ttb_crypto

import (
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "io/ioutil"
)

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// PUBLIC ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

type rsaPublicKey struct {
  *rsa.PublicKey
}

type rsaPublic interface {
  cypher(message string) (string, error)
  verify(message string, sig string) bool
}

func loadPublicKey(path string) (rsaPublic, error) {
  var block pem.Block
  if fileExists(path) == false {
    block, _ = pem.Decode([]byte(path))
    if block == nil {
      return nil, fmt.Errorf("Invalid path or the file does not exist: %s", path)
    }
  } else {
    pemBytes, err := ioutil.ReadFile(path)
    if err != nil {
      return nil, err
    }

    block, _ = pem.Decode(pemBytes)
    if block == nil {
      return nil, fmt.Errorf("ssh: no key found")
    }
  }

  var sshKey rsaPublic
  var rawkey interface{}
  switch block.Type {
  case "PUBLIC KEY":
    rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
      return nil, err
    }
    rawkey = rsa
  default:
    return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
  }

  switch t := rawkey.(type) {
  case *rsa.PublicKey:
    sshKey = &rsaPublicKey{t}
  default:
    return nil, fmt.Errorf("ssh: unsupported key type %T", rawkey)
  }
  return sshKey, nil
}

func (r *rsaPublicKey) cypher(message string) (data string , err error) {
  text, err := rsa.EncryptPKCS1v15(rand.Reader, r.PublicKey, []byte(message))
  if err == nil {
    data = encodeBase64(text)
  }
  return
}

func (r *rsaPublicKey) verify(message string, sig string) bool {
  h := sha256.New()
  h.Write([]byte(message))
  d := h.Sum(nil)
  err := rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, decodeBase64(sig))
  if err != nil {
    return false
  }
  return true
}


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// PRIVATE ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

type rsaPrivateKey struct {
  *rsa.PrivateKey
}

type rsaPrivate interface {
  uncypher(message string) (string, error)
  sign(message string) (string, error)
}

func loadPrivateKey(path string) (rsaPrivate, error) {
  var block pem.Block
  if fileExists(path) == false {
    block, _ = pem.Decode([]byte(path))
    if block == nil {
      return nil, fmt.Errorf("Invalid path or the file does not exist: %s", path)
    }
  } else {
    pemBytes, err := ioutil.ReadFile(path)
    if err != nil {
      return nil, err
    }

    block, _ = pem.Decode(pemBytes)
    if block == nil {
      return nil, fmt.Errorf("ssh: no key found")
    }
  }

  var sshKey rsaPrivate
  var rawkey interface{}
  switch block.Type {
  case "RSA PRIVATE KEY":
    rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
      return nil, err
    }
    rawkey = rsa
  default:
    return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
  }

  switch t := rawkey.(type) {
  case *rsa.PrivateKey:
    sshKey = &rsaPrivateKey{t}
  default:
    return nil, fmt.Errorf("ssh: unsupported key type %T", rawkey)
  }

  return sshKey, nil
}

func (r *rsaPrivateKey) uncypher(message string) (data string , err error)  {
  text, err := rsa.DecryptPKCS1v15(rand.Reader, r.PrivateKey, decodeBase64(message))
  if err == nil {
    data = string(text)
  }
  return
}

func (r *rsaPrivateKey) sign(message string) (data string , err error)  {
  h := sha256.New()
  h.Write([]byte(message))
  d := h.Sum(nil)

  text, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
  if err == nil {
    data = encodeBase64(text)
  }
  return
}
