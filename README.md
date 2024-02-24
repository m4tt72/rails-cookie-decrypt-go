# Rails Cookie Decrypt - Go

Decrypt Rails cookies in Go.

## Usage

```go
package main

import (
  "fmt"
  "github.com/m4tt72/rails-cookie-decrypt-go"
)

func main() {
  cookie := "..."

	options := rails_cookie_decrypt.Options{
		SecretKeyBase: "secret", // Rails secret_key_base
		Digest:        "sha256", // sha1 || sha256
		Unescape:      true,     // true || false, to unescape the value
	}

	value, err := rails_cookie_decrypt.Decrypt(cookie, options)
  if err != nil {
    fmt.Println(err)
  }

  fmt.Println(value)
}
```