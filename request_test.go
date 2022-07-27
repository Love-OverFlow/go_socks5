package go_socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestNewClientRequestMessage(t *testing.T) {
	tests := []struct {
		Version  byte
		Cmd      Command
		AddrType AddressType
		Address  []byte
		Port     []byte
		Err      error
		Message  ClientRequestMessage
	}{
		{
			Version:  socks5Version,
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{123, 35, 13, 89},
			Port:     []byte{0x00, 0x50},
			Err:      nil,
			Message: ClientRequestMessage{
				Cmd:      CmdConnect,
				AddrType: TypeIPv4,
				Address:  "123.35.13.89",
				Port:     0x0050,
			},
		},
		{
			Version:  0x00,
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{123, 35, 13, 89},
			Port:     []byte{0x00, 0x50},
			Err:      ErrVersionNotSupported,
			Message: ClientRequestMessage{
				Cmd:      CmdConnect,
				AddrType: TypeIPv4,
				Address:  "123.35.13.89",
				Port:     0x0050,
			},
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		buf.Write([]byte{test.Version, test.Cmd, ReservedFiled, test.AddrType})
		buf.Write(test.Address)
		buf.Write(test.Port)

		message, err := NewClientRequestMessage(&buf)
		if err != test.Err {
			t.Fatalf("should get error %s, but got %s\n", test.Err, err)
		}
		if err != nil {
			return
		}

		if *message != test.Message {
			t.Fatalf("should get message %v, but got %v\n", test.Message, *message)
		}
	}
}

func TestWriteRequestSuccessMessage(t *testing.T) {
	t.Run("write valid request success message", func(t *testing.T) {
		var buf bytes.Buffer
		ip := net.IP([]byte{123, 123, 11, 11})

		err := WriteRequestSuccessMessage(&buf, ip, 1081)
		if err != nil {
			t.Fatalf("error while writing: %s", err)
		}
		want := []byte{socks5Version, ReplySuccess, ReservedFiled, TypeIPv4, 123, 123, 11, 11, 0x04, 0x39}
		got := buf.Bytes()
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("message not match :want %v, but got %v", want, got)
		}
	})
}
