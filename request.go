package go_socks5

import (
	"io"
	"net"
)

const (
	IPv4Len = 4
	IPv6Len = 16
	PortLen = 2
)

type ClientRequestMessage struct {
	Cmd      Command
	AddrType AddressType
	Address  string
	Port     uint16
}

type Command = byte

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)

type AddressType = byte

const (
	TypeIPv4   AddressType = 0x01
	TypeDomain AddressType = 0x03
	TypeIPv6   AddressType = 0x04
)

type ReplyType = byte

const (
	ReplySuccess ReplyType = iota
	ReplyServerFailure
	ReplyConnectionNotAllowed
	ReplyNetworkUnreached
	ReplyHostUnreached
	ReplyConnectionRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	// Read version, command, reserved, address type
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	version, command, reserved, addrType := buf[0], buf[1], buf[2], buf[3]

	// check if the fields are valid
	if version != socks5Version {
		return nil, ErrVersionNotSupported
	}
	if command != CmdConnect && command != CmdBind && command != CmdUDP {
		return nil, ErrCommandNotSupported
	}
	if reserved != ReservedFiled {
		return nil, ErrInvalidReservedField
	}
	if addrType != TypeIPv4 && addrType != TypeIPv6 && addrType != TypeDomain {
		return nil, ErrAddressTypeNotSupported
	}

	// Read address
	message := ClientRequestMessage{
		Cmd:      command,
		AddrType: addrType,
	}
	switch addrType {
	case TypeIPv6:
		buf = make([]byte, IPv6Len)
		fallthrough
	case TypeIPv4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf)
		message.Address = ip.String()
	case TypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainLength := buf[0]
		if domainLength > IPv4Len {
			buf = make([]byte, domainLength)
		}
		if _, err := io.ReadFull(conn, buf[:domainLength]); err != nil {
			message.Address = string(buf[:domainLength])
		}
	}

	// Read Port number
	if _, err := io.ReadFull(conn, buf[:PortLen]); err != nil {
		return nil, err
	}
	message.Port = (uint16(buf[0]) << 8) + uint16(buf[1])

	return &message, nil
}

func WriteRequestSuccessMessage(conn io.Writer, ip net.IP, port uint16) error {
	addressType := TypeIPv4
	if len(ip) == IPv6Len {
		addressType = TypeIPv6
	}

	// Write version, reply success, reserved, address type
	_, err := conn.Write([]byte{socks5Version, ReplySuccess, ReservedFiled, addressType})
	if err != nil {
		return err
	}

	// Write bind IP(IPv4/IPv6)
	if _, err := conn.Write(ip); err != nil {
		return err
	}

	// Write bind Port
	buf := make([]byte, 2)
	buf[0] = byte(port >> 8)
	buf[1] = byte(port)
	_, err = conn.Write(buf)
	return err
}

func WriteRequestFailureMessage(conn io.Writer, replyType ReplyType) error {
	_, err := conn.Write([]byte{socks5Version, replyType, ReservedFiled, TypeIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
