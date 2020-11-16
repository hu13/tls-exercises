package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	resourcesDir := fmt.Sprintf("%v/../resources/client", cwd)
	rootCert := fmt.Sprintf("%v/ca.cert.pem", resourcesDir)

	// Read in the cert file
	rootCA, err := ioutil.ReadFile(rootCert)
	if err != nil {
		log.Fatal(err)
	}

	// // Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if !rootCAs.AppendCertsFromPEM(rootCA) {
		log.Fatal(fmt.Errorf("Not able to add the root CA"))
	}

	clientIntermCert := fmt.Sprintf("%v/client.intermediate.chain.pem", resourcesDir)
	clientCAKey := fmt.Sprintf("%v/client.key.pem", resourcesDir)
	cert, err := tls.LoadX509KeyPair(clientIntermCert, clientCAKey)
	if err != nil {
		log.Fatal(err)
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},

		InsecureSkipVerify: true, // Not actually skipping, we check the cert in VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Code copy/pasted and adapted from
			// https://github.com/golang/go/blob/81555cb4f3521b53f9de4ce15f64b77cc9df61b9/src/crypto/tls/handshake_client.go#L327-L344, but adapted to skip the hostname verification.
			// See https://github.com/golang/go/issues/21971#issuecomment-412836078.

			// If this is the first handshake on a connection, process and
			// (optionally) verify the server's certificates.
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("bitbox/electrum: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}

			opts := x509.VerifyOptions{
				Roots:         rootCAs,
				CurrentTime:   time.Now(),
				DNSName:       "", // <- skip hostname verification
				Intermediates: x509.NewCertPool(),
			}

			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			return err
		},
		RootCAs: rootCAs,
	}

	conn, err := tls.Dial("tcp", ":8080", conf)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Fatal("Expecting at least one single server cert")
	}

	ph, err := os.Open(fmt.Sprintf("%v/pinned.hash", resourcesDir))
	if err != nil {
		log.Fatal(err)
	}
	defer ph.Close()
	pinnedHash, err := ioutil.ReadAll(ph)
	if err != nil {
		log.Fatal(err)
	}
	remoteCertCheckSum := sha256.Sum256(certs[0].Raw)
	if bytes.Compare(pinnedHash, remoteCertCheckSum[:]) != 0 {
		log.Fatal(fmt.Errorf("pinned hash mismatched"))
	}

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
