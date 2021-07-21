package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
)

var rootCertList = make([]*x509.Certificate, 0)
var onlyOnce sync.Once

const (
	IosRootCertificate = "-----BEGIN CERTIFICATE-----MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD-----END CERTIFICATE-----"
)

type AttestationDetails struct {
	AttestationNonce []byte `asn1:"tag:1,explicit"`
}

type CustomError struct{}

func NewGolangHelper() *GolangHelperForCert {
	return &GolangHelperForCert{}
}

//AppAttestation -
type GolangHelperForCert struct {
}

func (m *CustomError) Error() string {
	return "Not able to process the request"
}

//Function for verifying the certificate chain against root certificate, in some cases we need to verify the certificate chain against root certificate
func (a *GolangHelperForCert) verifyCertChainAgainstRootCertificate(certs []*x509.Certificate) error {
	err := a.loadIosRootCerts()
	if err != nil {
		return err
	}

	parent := rootCertList[0]
	for i := len(certs) - 1; i >= 0; i-- {
		roots := x509.NewCertPool()
		roots.AddCert(parent)
		opts := x509.VerifyOptions{
			Roots: roots,
		}
		if err := certs[i].CheckSignatureFrom(parent); err != nil {
			return &CustomError{}
		}
		if _, err = certs[i].Verify(opts); err != nil {
			return &CustomError{}
		}
		parent = certs[i]
	}
	return nil
}

//Get the octet value encoded in x509 certificate extension using asn1 notation, here it takes the value from cert extn for ios
func ParseAndGetNonce(data []pkix.Extension) ([]byte, error) {
	var octet AttestationDetails
	for _, extension := range data {
		if extension.Id.String() == "1.2.840.113635.100.8.2" {
			if len(extension.Value) == 0 {
				return octet.AttestationNonce, &CustomError{}

			}
			_, err := asn1.Unmarshal(extension.Value, &octet)
			if err != nil {
				return octet.AttestationNonce, &CustomError{}
			}
			//attestationChallengeData := base64.StdEncoding.EncodeToString([]byte(att.AttestationNonce))
			return octet.AttestationNonce, nil
		}
	}
	return octet.AttestationNonce, nil
}

//To convert the public key in byte format also to hash pub key -> sha256.Sum256(pubKey)
func GetPublicKeyinBytes(certs *x509.Certificate) ([]byte, error) {
	publicKey := certs.PublicKey

	pubKey := []byte{}
	switch pub := publicKey.(type) {
	//if it is ec key it will fall in this case
	case *ecdsa.PublicKey:
		pubKey = elliptic.Marshal(pub, pub.X, pub.Y)

	default:
	}
	return pubKey, nil
}

//Method to verify the signature in a message against certificate public key
func verifySignature(cert *x509.Certificate, message, signature []byte) bool {

	type ECDSASignature struct {
		R, S *big.Int
	}
	publicKey := cert.PublicKey.(*ecdsa.PublicKey)

	e := &ECDSASignature{}
	msg := sha256.Sum256(message)
	_, err := asn1.Unmarshal(signature, e)
	if err != nil {
		return false
	}
	return ecdsa.Verify(publicKey, msg[:], e.R, e.S)
}

func (a *GolangHelperForCert) loadIosRootCerts() error {
	var cmErr error
	onlyOnce.Do(func() {
		rootCertArray := strings.Split(IosRootCertificate, ",")
		for _, certFromConfig := range rootCertArray {
			block, _ := pem.Decode([]byte(certFromConfig))

			if block == nil {
				cmErr = &CustomError{}
				return
			}
			iosRootcert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				cmErr = &CustomError{}
				return
			}
			rootCertList = append(rootCertList, iosRootcert)
		}
	})
	return cmErr
}

//Function to load x509 certificates from pem strings
/*
Sample PEM string ::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
IFNpZ25pbmcxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELsXe1jucNyoc6PZZ1HC+gAoLvrp2OYRC2uUxlc0XTttpsRERdei9p2MvNc++e
qh6L1DVluytBItt4JPr96ysEqOCAdgwggHUMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU2Rf+S2eQOEuS9NvO1VeAFAuPPckwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC
5hcHBsZS5jb20vb2NzcDAzLWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB/TCBwwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGF
ueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2Vy
dGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFIGCBRw26M+diRwFHH9m3uETI
OVTMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0gAMEUCIEbl6FNbfgVKn3/xjyoz1uGyGSpRZBDXeykfBquci6kTAiEAuHeXtKhLMS55fYtQ4yjVQbYt4ZdBgvJH8J
TG8orOCxYwggL5MIICf6ADAgECAhBW+4PUK/+NwzeZI7Varm69MAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXR
ob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE5MDMyMjE3NTMzM1oXDTM0MDMyMjAwMDAwMFowfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24g
Q0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASSzmO9f
YaxqygKOxzhr/sElICRrPYx36bLKDVvREvhIeVX3RKNjbqCfJW+Sfq+M8quzQQZ8S9DJfr0vrPLg366o4H3MIH0MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rLJK
swRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXB
wbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFNkX/ktnkDhLkvTbztVXgBQLjz3JMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIDBAIFADAKBggqhkjOPQQDAwNoADBlAjEAjW+mn6Hg5OxbTnOKkn89e
FOYj/TaH1gew3VK/jioTCqDGhqqDaZkbeG5k+jRVUztAjBnOyy04eg3B3fL1ex2qBo6VTs/NWrIxeaSsOFhvoBJaeRfK6ls4RECqsxh2Ti3c0owggJDMIIByaADAgECAggtxfyI0sVLlTAKBggqhkjOPQQ
DAzBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xNDA0M
zAxODE5MDZaFw0zOTA0MzAxODE5MDZaMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4
xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmOkvPUBypO2TInKBExzdEJXxxaNOcdwUFtkO5aYFKndke19OONO7HES1f/UftjJiXcnphFtPME8RWgD9WFgMpfUPLE0HRxN12peXl28xX
O0rnXsgO9i5VNlemaQ6UQoxo0IwQDAdBgNVHQ4EFgQUu7DeoVgziJqkipnevr3rr9rLJKswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAIPpwcQWXhpdNBj
Z7e/0bA4ARku437JGEcUP/eZ6jKGma87CA9Sc9ZPGdLhq36ojFQIwbWaKEMrUDdRPzY1DPrSKY6UzbuNt2he3ZB/IUyb5iGJ0OQsXW8tRqAzoGAPnorIoAAAxgfwwgfkCAQEwgZAwfDEwMC4GA1UEAwwnQ
XBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMCEFp
jJPW2ctrfH4W+ZDeqFOIwDQYJYIZIAWUDBAIBBQAwCgYIKoZIzj0EAwIERjBEAiBfcCLmUNUpgkqzXjbZZbmeyArZlFj3sFRjZULr/90vXQIgHsILdJtWhpluSgEPr5rKG2mZS2zFoFj9ZN/mlG2ZCOwAA
AAAAABoYXV0aERhdGFYpE6LTGG47VYTsKg3pc80DIXOKh+he7bQOJVWfe+vg60vQAAAAABhcHBhdHRlc3RkZXZlbG9wACBJwysA2ThaWdSuclP9RqTCjYlZ0qcjuQkGlI7Fga7HlaUBAgMmIAEhWCBVSpi
WWgYH8Bn9EBLR55zJ9e5UrtZZXA3q+2zIKnbfhiJYIJ1lttbJPlYFx0NAd2Szkosi0csmfx/fyk9RQEN2keiz
*/

func LoadCertificates(pems []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, data := range pems {
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, &CustomError{}
		}
		cert, err := x509.ParseCertificate(decoded)
		if err != nil {

			return nil, &CustomError{}
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
