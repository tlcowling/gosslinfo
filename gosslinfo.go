package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
    "os"
)

func main() {
    if len(os.Args) == 1 {
        fmt.Println("Usage: gosslinfo HTTPS_ADDRESS")
        os.Exit(1)
    }
    arg := os.Args[1]
	resp, _ := http.Get(arg)
	info(resp)
}

func info(r *http.Response) {
	fmt.Println("Status: ", r.Status)
	if r.TLS != nil {
		sslinfo(r.TLS)
	} else {
        fmt.Println("Not a HTTPS request, try again with https")
    }
}

func lookupversion(v uint16) string {
   var versionlookup = map[uint16]string {
        tls.VersionSSL30: "SSL30",
        tls.VersionTLS10: "TLS10",
        tls.VersionTLS11: "TLS11",
        tls.VersionTLS12: "TLS12",
   }

   return versionlookup[v]
}

func lookupconst(v uint16) string {

	var constLookup = map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_FALLBACK_SCSV:                       "TLS_FALLBACK_SCSV",
	}
	return constLookup[v]
}

func sslinfo(state *tls.ConnectionState) {
	fmt.Printf("TLS Version: %v\n", lookupversion(state.Version))
	fmt.Printf("Handshake Complete?: %v\n", state.HandshakeComplete)
	fmt.Printf("Resuming a previous TLS Connection?: %v\n", state.DidResume)
	fmt.Printf("Cipher Suite: %v\n", lookupconst(state.CipherSuite))
	fmt.Printf("Negotiated Protocol: %v\n", state.NegotiatedProtocol)
	fmt.Printf("Negotiated Protocol Is Mutual?: %v\n", state.NegotiatedProtocolIsMutual)
    fmt.Printf("Peer Certificates %v\n", state.PeerCertificates)
    fmt.Printf("Verified Chains %v\n", state.VerifiedChains)

}
