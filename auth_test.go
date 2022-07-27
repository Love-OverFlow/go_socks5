package go_socks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{socks5Version, 2, MethodNoAuth, MethodGSSAPI}
		r := bytes.NewReader(b)

		message, err := NewClientAuthMessage(r)
		if err != nil {
			t.Fatalf("want error == nil but got %s", err)
		}

		if message.Version != socks5Version {
			t.Fatalf("want socks5Version but got %d", message.Version)
		}
		if message.NMethods != 2 {
			t.Fatalf("want nMethods == 2 but got %d", message.NMethods)
		}
		if !reflect.DeepEqual(message.Methods, []byte{MethodNoAuth, MethodGSSAPI}) {
			t.Fatalf("want methods: %v, but got %v", []byte{MethodNoAuth, MethodGSSAPI}, message.Methods)
		}
	})

	t.Run("methods' length is shorter than nMethods", func(t *testing.T) {
		b := []byte{socks5Version, 2, MethodNoAuth}
		r := bytes.NewReader(b)

		_, err := NewClientAuthMessage(r)
		if err == nil {
			t.Fatalf("should get error != nil but got nil")
		}
	})

	t.Run("wrong version test", func(t *testing.T) {
		b := []byte{0x04, 2, MethodNoAuth, MethodGSSAPI}
		r := bytes.NewReader(b)

		_, err := NewClientAuthMessage(r)
		if err == nil {
			t.Fatalf("should get error != nil but got nil")
		}
	})

}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("shuld pass", func(t *testing.T) {
		var buf bytes.Buffer
		err := newServerAuthMessage(&buf, MethodNoAuth)
		if err != nil {
			t.Fatalf("should get nil but got %s", err)
		}

		b := buf.Bytes()
		if !reflect.DeepEqual(b, []byte{socks5Version, MethodNoAuth}) {
			t.Fatalf("should send %v, but send %v instead", []byte{socks5Version, MethodNoAuth}, b)
		}
	})
}

func TestNewClientPasswordMessage(t *testing.T) {
	t.Run("valid password auth message", func(t *testing.T) {
		var buf bytes.Buffer
		username, password := "admin", "123456"
		buf.Write([]byte{PasswordMethodVersion, 5})
		buf.WriteString(username)
		buf.WriteByte(6)
		buf.WriteString(password)

		message, err := NewClientPasswordMessage(&buf)
		if err != nil {
			t.Fatalf("want error == nil but got %s", err)
		}

		want := ClientPasswordMessage{
			Username: username,
			Password: password,
		}
		if *message != want {
			t.Fatalf("want message %#v but got %#v", *message, want)
		}
	})
}
