package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	resources_dir := fmt.Sprintf("%v/../resources/client", cwd)
	client_ca_cert := fmt.Sprintf("%v/ca.cert.pem", resources_dir)

	// Read in the cert file
	ca_cert, err := ioutil.ReadFile(client_ca_cert)
	if err != nil {
		log.Fatal(err)
	}

	// // Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if !rootCAs.AppendCertsFromPEM(ca_cert) {
		log.Fatal(err)
	}

	client_ca_inter_cert := fmt.Sprintf("%v/client.intermediate.chain.pem", resources_dir)
	client_ca_key := fmt.Sprintf("%v/client.key.pem", resources_dir)
	cert, err := tls.LoadX509KeyPair(client_ca_inter_cert, client_ca_key)
	if err != nil {
		log.Fatal(err)
	}

	conf := &tls.Config{
		// InsecureSkipVerify: true,
		// ServerName: "Expert TLS Server",
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
	}

	conn, err := tls.Dial("tcp", "localhost:8080", conf)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	read(conn)
}

func read(conn net.Conn) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		switch {
		case err == io.EOF, err == nil:
			fmt.Println(buf[:n])
			return
		case err != nil:
			panic(err)
		}
	}
}
