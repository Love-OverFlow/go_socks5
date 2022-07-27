package go_socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	socks5Version = 0x05
	ReservedFiled = 0x00
)

var (
	ErrVersionNotSupported         = errors.New("protocol version not supported")
	ErrPasswordVersionNotSupported = errors.New("sub-negotiation method (password) version not supported")
	ErrCommandNotSupported         = errors.New("request command not supported")
	ErrInvalidReservedField        = errors.New("invalid reserved field")
	ErrAddressTypeNotSupported     = errors.New("address type not supported")
)

type Server interface {
	Run() error
}

type Socks5Server struct {
	IP     string
	Port   int
	Config *Config
}

type Config struct {
	AuthMethod      Method
	PasswordChecker func(username, password string) bool
	TCPTimeout      time.Duration
}

func initConfig(config *Config) error {
	if config.AuthMethod == MethodPassWord && config.PasswordChecker == nil {
		return ErrPasswordCheckerNotSet
	}
	return nil
}

func (s *Socks5Server) Run() error {
	// Initialize server configuration
	if err := initConfig(s.Config); err != nil {
		return err
	}

	// Listen on the specified IP:PORT
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	for {
		// 三次握手，再从已经三次握手的队列中返回一个TCP连接(conn)
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Connection failure from %s: %s", conn.RemoteAddr(), err)
			continue
		}

		// goroutine
		// 外层包裹一个匿名函数用于处理error
		go func() {
			// defer常用于资源的释放,会在函数返回之前调用,经常被用于关闭文件描述符、关闭数据库连接以及解锁资源
			// 不管函数的执行是否panic，defer都会执行，这样就保证了资源的释放
			defer conn.Close()
			err := s.handleConnection(conn, s.Config)
			if err != nil {
				log.Printf("Handle connection failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func (s *Socks5Server) handleConnection(conn net.Conn, config *Config) error {
	// 协商过程
	if err := auth(conn, config); err != nil {
		return err
	}

	// 请求、转发过程
	return s.request(conn)
}

func auth(conn io.ReadWriter, config *Config) error {
	// Read Client's auth request message
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}

	// Check if the auth method is supported
	acceptable := false
	for _, method := range clientMessage.Methods {
		if method == config.AuthMethod {
			acceptable = true
			break
		}
	}
	if !acceptable {
		err := newServerAuthMessage(conn, MethodNoAcceptable)
		if err != nil {
			return err
		}
		return errors.New("method not supported")
	}
	if err := newServerAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}

	if config.AuthMethod == MethodPassWord {
		cpm, err := NewClientPasswordMessage(conn)
		if err != nil {
			return err
		}

		if !config.PasswordChecker(cpm.Username, cpm.Password) {
			WriteServerPasswordMessage(conn, PasswordAuthFailure)
			return ErrPasswordAuthFailure
		}

		if err := WriteServerPasswordMessage(conn, PasswordAuthSuccess); err != nil {
			return err
		}
	}

	return nil
}

func (s *Socks5Server) request(conn io.ReadWriter) error {
	// Read client request message from connection
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return err
	}

	// Check if the address type is supported
	if message.AddrType == TypeIPv6 {
		WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
		return ErrAddressTypeNotSupported
	}

	if message.Cmd == CmdConnect {
		return s.handleTCP(conn, message)
	} else if message.Cmd == CmdUDP {
		return s.handleUDP()
	} else {
		WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
		return ErrCommandNotSupported
	}

}

func (s *Socks5Server) handleTCP(conn io.ReadWriter, message *ClientRequestMessage) error {
	// Request access to the target TCP service
	address := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.DialTimeout("tcp", address, s.Config.TCPTimeout)
	if err != nil {
		WriteRequestFailureMessage(conn, ReplyConnectionRefused)
		return err
	}

	// Send success reply
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	if err := WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port)); err != nil {
		return err
	}

	return forward(conn, targetConn)
}

func (s *Socks5Server) handleUDP() error {
	// TODO
	return nil
}

func forward(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	defer targetConn.Close()
	go io.Copy(targetConn, conn)
	_, err := io.Copy(conn, targetConn)
	return err
}
