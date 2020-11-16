package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func main() {
	fmt.Println("server begins...")

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	resourcesDir := fmt.Sprintf("%v/../resources/server", cwd)

	server_ca_cert := fmt.Sprintf("%v/ca.cert.pem", resourcesDir)
	ca_cert, err := ioutil.ReadFile(server_ca_cert)
	if err != nil {
		log.Fatal(err)
	}
	pools := x509.NewCertPool()
	if !pools.AppendCertsFromPEM(ca_cert) {
		log.Fatal(err)
	}

	serverCAIntermCert := fmt.Sprintf("%v/server.intermediate.chain.pem", resourcesDir)
	serverCAKey := fmt.Sprintf("%v/server.key.pem", resourcesDir)
	cert, err := tls.LoadX509KeyPair(serverCAIntermCert, serverCAKey)
	if err != nil {
		log.Fatal(err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pools,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	ln, err := tls.Listen("tcp", ":8080", cfg)
	if err != nil {
		// handle error
		panic(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
			fmt.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	fmt.Println("responding ...")
	conn.Write([]byte("asdfasdf"))
}
