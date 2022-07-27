package go_socks5

import (
	"errors"
	"io"
)

type Method = byte

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassWord     Method = 0x02
	MethodNoAcceptable Method = 0xFF
)

const (
	PasswordMethodVersion = 0x01
	PasswordAuthSuccess   = 0x00
	PasswordAuthFailure   = 0x01
)

var (
	ErrPasswordCheckerNotSet = errors.New("error password checker not set")
	ErrPasswordAuthFailure   = errors.New("error while authenticating username/password")
)

type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

type ClientPasswordMessage struct {
	Username string
	Password string
}

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	// 读取Version，nMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	// 协议版本验证
	if buf[0] != socks5Version {
		return nil, ErrVersionNotSupported
	}

	// 读取协商方法
	nMethods := buf[1]
	buf = make([]byte, nMethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version:  socks5Version,
		NMethods: nMethods,
		Methods:  buf,
	}, nil
}

func newServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{socks5Version, method}
	_, err := conn.Write(buf)
	return err
}

func NewClientPasswordMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	// Read version and username length
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	version, usernameLen := buf[0], buf[1]
	if version != PasswordMethodVersion {
		return nil, ErrPasswordVersionNotSupported
	}

	// Read username
	buf = make([]byte, usernameLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	username, passwordLen := string(buf[:len(buf)-1]), buf[len(buf)-1]

	// Read password
	if len(buf) < int(passwordLen) {
		buf = make([]byte, passwordLen)
	}
	if _, err := io.ReadFull(conn, buf[:passwordLen]); err != nil {
		return nil, err
	}

	return &ClientPasswordMessage{
		Username: username,
		Password: string(buf[:passwordLen]),
	}, nil

}

func WriteServerPasswordMessage(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordMethodVersion, status})
	return err
}
