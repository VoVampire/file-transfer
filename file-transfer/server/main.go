package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"os"
)

func main() {
	listener, err := net.Listen("tcp", "localhost:8000")
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// 读取客户端发送的内容
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println("conn.Read err: ", err)
		return
	}

	addr := conn.RemoteAddr().String()
	fileName := string(buf[:n])
	log.Println(addr + ": upload file - " + fileName)

	// 告诉客户端已经接收到文件名
	conn.Write([]byte("ok"))

	//创建文件
	file, err := os.Create(fileName)
	if err != nil {
		log.Println(err)
		return
	}
	defer file.Close()

	// 循环接收客户端传递的文件内容
	for {
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println("conn.Read err: ", err)
			return
		}

		if string(buf[:n]) == "finish" {
			log.Println(addr + ": upload complete")
			return
		}

		origData, err := rsaDecrypt(buf)
		if err != nil {
			log.Println("rsaDecrypt err: ", err)
			return
		}

		file.Write(origData)
	}
}

// 解密
func rsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC1wIKMnvy29LMWrQmzl751/JrSS7mLlWOOMdfTzAiXNe4I1iDh
KPVPZP/tnARQi6iUKgV28hhsRNqjpfRXYAg2aSq7khRdh6R6RXTrTeCP5yPbQMF1
xqbuUqgXY+tEh78Q23z9XkHbdOo5jKlI3/SGidwzTHDVGgrxb2s/cmeYgQIDAQAB
AoGAQ033yjUx5lp1W0dW2V+vEygo+Qk7u5nllQmWIANlhwFclX8eC+NL/EutjoMB
AgbFtaBeB68dJjLVOFbDRfv07fhwfLdQHVxjlwVEMQdjQQ8ax8kiFYbHElcSLjYV
D4e+37TQqWmfZBaa9vc+0MDUUic1oAUZHHx/Kb9ybYYhZUUCQQDAPZOufz5ZknNb
7S+F8aieMGJG45YpbD9Cct+SKA7s9ToFBjiHSFaepIM0yEuz8k4zlqrPyOzHrypA
JNVcK45rAkEA8ghj5rIyXLy6X9FxYHM35G/MLtpVMvU+A6Oi107ipKsFv/s5JNBM
dKVeucqwh90ZrXpWEX4xXPwG/wu2cOuXwwJAQUTm3kkPd0P07NIj33tD/6l3xI/C
zP+Wns33wFzfbG56K3iIOs5Bso0yivoyUb9D89oE1pVmZwm+85ZN5oRXTwJALcHU
UTsDNnEfsxm/m4Js4K0aJwlz7gxbSwjWsmnhg0wp7B+sr/8JVUwmWm2tbiIoxplI
SEpZPsEO+YzXUwXXTQJAavS+KZt5cLRTOqykj1zxjt4WegoI4oiQU7+DZqipdvLh
rgTksCAraBpLq3nILqPepLui+APlV4Jhm+ao17rhvA==
-----END RSA PRIVATE KEY-----`))
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
