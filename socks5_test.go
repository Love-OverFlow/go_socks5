package go_socks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestAuth(t *testing.T) {
	config := Config{
		AuthMethod:      MethodNoAuth,
		PasswordChecker: nil,
	}
	t.Run("a valid client auth message", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{socks5Version, 2, MethodNoAuth, MethodGSSAPI})
		err := auth(&buf, &config)
		if err != nil {
			t.Fatalf("should get nil but got %s", err)
		}
		res := buf.Bytes()
		if !reflect.DeepEqual(res, []byte{socks5Version, MethodNoAuth}) {
			t.Fatalf("should send %v, but send %v instead", []byte{socks5Version, MethodNoAuth}, res)
		}
	})

	t.Run("a invalid client auth message", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{socks5Version, 2, MethodNoAuth})
		err := auth(&buf, &config)
		if err == nil {
			t.Fatalf("should get error but got nil")
		}

	})
}
