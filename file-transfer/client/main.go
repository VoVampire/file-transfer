package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	// 读取文件
	filePath := os.Args[1]
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Println("os.Stat err: ", err)
		return
	}
	fileName := fileInfo.Name()

	// 连接服务器
	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		log.Println("net.Dial err: ", err)
		return
	}
	defer conn.Close()

	// 发送文件名称到服务器
	_, err = conn.Write([]byte(fileName))
	if err != nil {
		log.Println("conn.Write err: ", err)
		return
	}

	// 接收服务器返还的指令
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println("conn.Read err: ", err)
		return
	}

	//返回ok，可以传输文件
	if string(buf[:n]) == "ok" {
		uploadFile(filePath, conn)
	}
}

func uploadFile(filePath string, conn net.Conn) {
	//打开要传输的文件
	file, err := os.Open(filePath)
	if err != nil {
		log.Println("os.Open err", err)
		return
	}
	defer file.Close()

	//循环读取文件内容，写入远程连接
	buf := make([]byte, 117)
	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			conn.Write([]byte("finish"))
			break
		}
		if err != nil {
			log.Println("file.Read err:", err)
			return
		}
		ciphertext, err := rsaEncrypt(buf[:n])
		if err != nil {
			log.Println("rsaEncrypt err:", err)
			return
		}

		_, err = conn.Write(ciphertext)
		if err != nil {
			log.Println("conn.Write err:", err)
			return
		}
	}
	log.Println("upload complete")
}

func rsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1wIKMnvy29LMWrQmzl751/JrS
S7mLlWOOMdfTzAiXNe4I1iDhKPVPZP/tnARQi6iUKgV28hhsRNqjpfRXYAg2aSq7
khRdh6R6RXTrTeCP5yPbQMF1xqbuUqgXY+tEh78Q23z9XkHbdOo5jKlI3/SGidwz
THDVGgrxb2s/cmeYgQIDAQAB
-----END PUBLIC KEY-----`))
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}
