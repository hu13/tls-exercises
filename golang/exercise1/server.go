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
	resources_dir := fmt.Sprintf("%v/../resources/server", cwd)

	server_ca_cert := fmt.Sprintf("%v/ca.cert.pem", resources_dir)
	ca_cert, err := ioutil.ReadFile(server_ca_cert)
	if err != nil {
		log.Fatal(err)
	}
	pools := x509.NewCertPool()
	if !pools.AppendCertsFromPEM(ca_cert) {
		log.Fatal(err)
	}

	server_ca_inter_cert := fmt.Sprintf("%v/server.intermediate.chain.pem", resources_dir)
	server_ca_key := fmt.Sprintf("%v/server.key.pem", resources_dir)
	cert, err := tls.LoadX509KeyPair(server_ca_inter_cert, server_ca_key)
	if err != nil {
		log.Fatal(err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pools,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	cfg.BuildNameToCertificate()
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
