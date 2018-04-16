package ttb_crypto

import (
  "bytes"
  "fmt"
  "strings"
)

type Message interface {
  ReadMessage() (string, error)
  ToString() string
  Verify() bool
}

type message struct {
  public            rsaPublic
  private           rsaPrivate
  algo              string
  keys              []string
  signature         string
  cypher            string
}

func CreateMessage(msg string, algo string, rsaPublicPath string, rsaPrivatePath string) (Message, error){
  var m Message
  var keys []string
  var signature string
  var cypher string

  algoNumber := indexString(KNOWN_ALGO, algo)

  if algoNumber == -1 {
    return nil, fmt.Errorf("Unknown algo : %s", algo)
  }

  public, puberr := loadPublicKey(rsaPublicPath)
  if puberr != nil {
    return nil, puberr
  }

  private, priverr := loadPrivateKey(rsaPrivatePath)
  if priverr != nil {
    return nil, priverr
  }

  switch algoNumber {
  case 0:
    k, i, err := genAesGcmKeys()
    aes := loadAesGcm(k, i)
    if err != nil {
      return nil, err
    }

    kg, err := public.cypher(k)
    if err != nil {
      return nil, err
    }
    keys = append(keys, kg)
    ig, err := public.cypher(i)
    if err != nil {
      return nil, err
    }
    keys = append(keys, ig)

    signature, _ = private.sign(hashSha1(k))
    cypher, _ = aes.cypher(msg)
    break
  }

  m =  &message{public, private, algo, keys, signature, cypher}
  return m, nil
}

func LoadMessage(msg string, rsaPublicPath string, rsaPrivatePath string) (Message, error) {
  var m Message

  var data []string
  var algo string
  var keys []string
  var signature string
  var cypher string

  public, puberr := loadPublicKey(rsaPublicPath)
  if puberr != nil {
    return nil, puberr
  }

  private, priverr := loadPrivateKey(rsaPrivatePath)
  if priverr != nil {
    return nil, priverr
  }

  start := 0
  end := 0
  i := 0

  for i < len(msg) {
    start, end = parseSlice(msg[i:])
    if start == -1 || end == -1 {
      break
    }
    data = append(data, msg[i+start:i+end])
    i = i+end
  }

  if len(data) < 4 {
    return nil, fmt.Errorf("Bad format message")
  }

  algo = strings.ToLower(data[0])

  if indexString(KNOWN_ALGO, algo) == -1 {
      return nil, fmt.Errorf("Unknown algo : %s", algo)
  }

  nbKey := len(data) - 3

  for index := 0 ; index < nbKey; index++ {
    keys = append(keys, data[1+index])
  }

  signature = data[len(data)-2]
  cypher = data[len(data)-1]

  m =  &message{public, private, algo, keys, signature, cypher}
  return m, nil
}

func (msg *message) ReadMessage() (data string, err error) {
  var clearedKeys []string
  for index := 0; index < len(msg.keys); index++ {
    k, err := msg.private.uncypher(msg.keys[index])
    if err != nil {
      return data, err
    }
    clearedKeys = append(clearedKeys, k)
  }

  algoNumber := indexString(KNOWN_ALGO, msg.algo)

  if algoNumber == -1 {
    err = fmt.Errorf("Unknown algo : %s", msg.algo)
    return
  }

  switch algoNumber {
  case 0:
    aes := loadAesGcm(clearedKeys[0], clearedKeys[1])
    data, err = aes.uncypher(msg.cypher)
  }

  return
}

func (msg *message) ToString() string {
  var m bytes.Buffer
  m.WriteString(createSlice(msg.algo))
  for index := 0; index < len(msg.keys); index++ {
    m.WriteString(createSlice(msg.keys[index]))
  }
  m.WriteString(createSlice(msg.signature))
  m.WriteString(createSlice(msg.cypher))
  return m.String()
}

func (msg *message) Verify() bool {
  key, err := msg.private.uncypher(msg.keys[0])
  if err != nil {
    return false
  }
  return msg.public.verify(hashSha1(key), msg.signature)
}
