package rails_cookie_decrypt_test

import (
	"testing"

	rails_cookie_decrypt "github.com/m4tt72/rails-cookie-decrypt-go"
)

func TestDecrypt(t *testing.T) {
	cookie := "OQCGvZ%2BGaP5%2Bw4alPQIbeCIgP7Exb%2Bs2%2BGN%2BMTx3LklGqKXEbwSDObNVudeVm8Bm4l7tjlNEnxnnl9h9ANRoHNM8EuGnVjl8az3qn6sBQFh85eg9NyItZ9MP4TbI3Dscpqlr1UICB5DlkkKl67Lhk909dPfUK%2FJkhpNWvxUuip2M%2BS0sOQd0TgXdlMFG5JLDwj%2FoGaZ8X%2BdCz%2BMKkXY10wqbEz334%2FGKmOAS2CIdYMnRpU%2BDCVRvJf9gil4RxF3e2dCyIcyquBko9Zz2LjdN--bF3MnKOse2ug9ysc--1yhdFSFOe%2FATp0%2B4Ul9g3A%3D%3D"

	options := rails_cookie_decrypt.Options{
		SecretKeyBase: "secret",
		Digest:        "sha256",
		Unescape:      true,
	}

	got, err := rails_cookie_decrypt.Decrypt(cookie, options)
	if err != nil {
		t.Fatal(err)
	}

	want := "{\"_rails\":{\"message\":\"eyJzZXNzaW9uX2lkIjoiODZhZDc2MjUxNTFiMTc1YzFlZDQzOGZkNjFjZTI5MTAiLCJfY3NyZl90b2tlbiI6IlBESHZVZTdkLWk5d3N3S2U4bGZOQ1pmeThaRzd1R3ZKQWZqRm1sR2VaYXMifQ==\",\"exp\":null,\"pur\":\"cookie.session\"}}"

	if got != want {
		t.Errorf("got %s; want %s", got, want)
	}
}
