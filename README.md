# ttb-crypto

### Sample

``` go
package main

import (
    "github.com/TheThingBox/ttb-crypto"
    "fmt"
    "flag"
)

var param_private_key string
var param_public_key string
var param_algo string
var param_text string
var param_action string

func main() {
  flag.StringVar(&param_private_key, "private_key", "", "The RSA private key path")
  flag.StringVar(&param_public_key, "public_key", "", "The RSA public key path")
  flag.StringVar(&param_algo, "algo", "aes-256-gcm", "The algorithm")
  flag.StringVar(&param_text, "text", "", "The content to encrypt / decrypt")
  flag.StringVar(&param_action, "action", "encrypt", "encrypt or decrypt")
  flag.Parse()

  if param_action != "encrypt" &&  param_action != "decrypt" {
    fmt.Println("Invalid setting for -action, must be decrypt or encrypt not :", param_action)
    return
  }

  if param_private_key == "" {
    fmt.Println("Invalid setting for -private_key, must not be empty")
    return
  }

  if param_public_key == "" {
    fmt.Println("Invalid setting for -public_key, must not be empty")
    return
  }

  if param_action == "encrypt" {
    fmt.Println("Original message :\n",param_text)
    msg, err := ttb_crypto.CreateMessage(param_text, param_algo, param_public_key, param_private_key)
    if err != nil {
      fmt.Println(err.Error())
      return
    }
    fmt.Println("Cyphered message :\n",msg.ToString())
  } else {
    msg, err := ttb_crypto.LoadMessage(param_text, param_public_key, param_private_key)
    if err != nil {
      fmt.Println(err.Error())
      return
    }
    data, err := msg.ReadMessage()
    if err != nil {
      fmt.Println(err.Error())
      return
    }
    fmt.Println("Original message :\n", data)
    v := msg.Verify()
    fmt.Println("Verified message :\n", v)
  }

}

```

### Output :

``` bash
root@211c03bee751:/usr/src/crypto# ./crypto -private_key ./private.pem -public_key ./public.pem  -action encrypt -text coucou
Original message :
 coucou
Cyphered message :
 0x01baes-256-gcm0x03158z9M61+KtUPdq7Cet+dau1SdvHPDL0ZrniIjw6tYuTPO2cTWgAS6X7wJEl7LAcgZcYxfV7vP9JHYNY3zv5zldnGmFzoa0aeMZ/RTII4+BRMLJchPLHwGdLvDEx8HhyYo9nPl+H9AxCfZ0bAMZxneV4FYvVAVL9AsZ00qhJ8+TqPCkotCXTQHOxqOezhy0FvyDh+Jg8rryH/XWL9CQ04vX18He+cGgTrkwLaKc/TrgEVEdYHtQQIwbO+CtYobG8pi9SORF8N5nN9vZDWFSIcbL/LlVEllBUr8B8WkRG8YP2kQxn9Ai+aMTVVtGkZJMd7U4ibxAgFC3N8b/fkVyfD8R3A==0x03158Tg54JEAIbC2oI5nKb13OalkVsheufHmwMQmEPui7AacGJ+psk3n0pcP+s02/toEjTkFs8yHmH5h39DC899M8l1fwXFsLWAbgqV+Sv6hPwf+nIceELCWFAuZ2+iqLt0CFzKhzswPtiUrewp4DK4aQuTcSE5LDWSFxR61wVhtc7y8g4E/3q4BCK2Je/X7Dl4+UmBx477ZSEAl18n815uNhrTmCctKTmU6M2UQqxRhl/qgmrhEk2Pmpx0V0eftZo1i6iHXe3isSHmd+Wfg78U+nY0k3L9n4ULG+W0qk7UjkY1DAWSqvj2HCh2fD79SJ+LzMfXlFu+zsO3QRdCnBrdfXpg==0x03158pPeO4u0tYpcQNmnPq+e1EZ9UX1UpvdNa/5bGuN+yAV5qRlfe5Qp7kmXAFjpXS9F0U1WBiAiSImh5OxTFb2d2VTsKgHRitcz3VrhjwboCBoe54CgOjlbz2reBGEKUynhqsvfUoRWjgpqQh95G/M9ylkujBnS6FWilRsUSaxVEl3g7+BxJxGrAx4sYtWWLi5TDDd8VCO1qWjJLKhTBJG2EzhYga5VziLLn0oqKrUOgJnokZ9Ues5qio2QloczZEN69kja6yRXIYpU5n6eDPtZyy12yy0jVRMKCYTx/MeO8B7xSQLzcPE80kRDRB7qng9Ik6jU3mDyw7eoCWQV6lgobAQ==0x022c68cb993ea2817c9983cdcba957ffe850e6d80e8491d9
```

``` bash
root@211c03bee751:/usr/src/crypto# ./crypto -private_key ./private.pem -public_key ./public.pem  -action decrypt -text 0x01baes-256-gcm0x03158z9M61+KtUPdq7Cet+dau1SdvHPDL0ZrniIjw6tYuTPO2cTWgAS6X7wJEl7LAcgZcYxfV7vP9JHYNY3zv5zldnGmFzoa0aeMZ/RTII4+BRMLJchPLHwGdLvDEx8HhyYo9nPl+H9AxCfZ0bAMZxneV4FYvVAVL9AsZ00qhJ8+TqPCkotCXTQHOxqOezhy0FvyDh+Jg8rryH/XWL9CQ04vX18He+cGgTrkwLaKc/TrgEVEdYHtQQIwbO+CtYobG8pi9SORF8N5nN9vZDWFSIcbL/LlVEllBUr8B8WkRG8YP2kQxn9Ai+aMTVVtGkZJMd7U4ibxAgFC3N8b/fkVyfD8R3A==0x03158Tg54JEAIbC2oI5nKb13OalkVsheufHmwMQmEPui7AacGJ+psk3n0pcP+s02/toEjTkFs8yHmH5h39DC899M8l1fwXFsLWAbgqV+Sv6hPwf+nIceELCWFAuZ2+iqLt0CFzKhzswPtiUrewp4DK4aQuTcSE5LDWSFxR61wVhtc7y8g4E/3q4BCK2Je/X7Dl4+UmBx477ZSEAl18n815uNhrTmCctKTmU6M2UQqxRhl/qgmrhEk2Pmpx0V0eftZo1i6iHXe3isSHmd+Wfg78U+nY0k3L9n4ULG+W0qk7UjkY1DAWSqvj2HCh2fD79SJ+LzMfXlFu+zsO3QRdCnBrdfXpg==0x03158pPeO4u0tYpcQNmnPq+e1EZ9UX1UpvdNa/5bGuN+yAV5qRlfe5Qp7kmXAFjpXS9F0U1WBiAiSImh5OxTFb2d2VTsKgHRitcz3VrhjwboCBoe54CgOjlbz2reBGEKUynhqsvfUoRWjgpqQh95G/M9ylkujBnS6FWilRsUSaxVEl3g7+BxJxGrAx4sYtWWLi5TDDd8VCO1qWjJLKhTBJG2EzhYga5VziLLn0oqKrUOgJnokZ9Ues5qio2QloczZEN69kja6yRXIYpU5n6eDPtZyy12yy0jVRMKCYTx/MeO8B7xSQLzcPE80kRDRB7qng9Ik6jU3mDyw7eoCWQV6lgobAQ==0x022c68cb993ea2817c9983cdcba957ffe850e6d80e8491d9
Original message :
 coucou
Verified message :
 true
```
