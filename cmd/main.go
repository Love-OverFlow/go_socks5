package main

import (
	"github.com/Love-OverFlow/go_socks5"
	"log"
	"sync"
	"time"
)

func main() {
	users := map[string]string{
		"admin":    "123456",
		"zhangsan": "1234",
		"lisi":     "abde",
	}

	var mutex sync.Mutex

	server := go_socks5.Socks5Server{
		IP:   "localhost",
		Port: 1080,
		Config: &go_socks5.Config{
			AuthMethod: go_socks5.MethodPassWord,
			PasswordChecker: func(username, password string) bool {
				mutex.Lock()
				defer mutex.Unlock()
				wantPassword, ok := users[username]
				if !ok {
					return false
				}
				return wantPassword == password
			},
			TCPTimeout: 5 * time.Second,
		},
	}

	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}
