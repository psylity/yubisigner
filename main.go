package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"hash"
	"io"
	"math/big"
	"os"
	"strings"
)

var log = logrus.New()

func VerifySignature(input io.Reader, signature []byte, signerCertificate, CA *x509.Certificate, hashAlgo crypto.Hash) (bool, error) {
	roots := x509.NewCertPool()
	roots.AddCert(CA)

	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}

	log.Debugf("verifying signer certificate")
	if _, err := signerCertificate.Verify(options); err != nil {
		return false, fmt.Errorf("failed to verify signer certificate: %w", err)
	}

	log.Debugf("generating data digest (%v)", hashAlgo)

	var hasher hash.Hash
	switch hashAlgo {
	case crypto.SHA1:
		hasher = sha1.New()
	case crypto.SHA256:
		hasher = sha256.New()
	case crypto.SHA512:
		hasher = sha512.New()
	default:
		return false, fmt.Errorf("unsupported hashing algorithm: %v", hashAlgo)
	}
	_, err := io.Copy(hasher, input)
	if err != nil {
		return false, fmt.Errorf("failed to calculate data hash: %w", err)
	}
	digest := hasher.Sum(nil)
	log.Debugf("digest calculated")

	switch pub := signerCertificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		log.Debugf("got ecdsa key")
		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			return false, fmt.Errorf("ecdsa asn1 Unmarshal failed: %w", err)
		}
		return ecdsa.Verify(pub, digest, esig.R, esig.S), nil

	case ed25519.PublicKey:
		log.Debugf("got ed25519 key")
		verified := ed25519.Verify(pub, digest, signature)
		return verified, nil

	case *rsa.PublicKey:
		log.Debugf("got rsa key")
		err = rsa.VerifyPKCS1v15(pub, hashAlgo, digest, signature)
		return err == nil, nil
	}

	return false, fmt.Errorf("unsupported public key type: %T", signerCertificate.PublicKey)
}

func VerifySignatureWrapper(inputFile, signFile, caFile string, hashAlgo crypto.Hash) (bool, error) {
	var reader *bufio.Reader
	if inputFile == "-" {
		log.Debugf("reading from standard input")
		reader = bufio.NewReader(os.Stdin)
	} else {
		log.Debugf("reading from %s", inputFile)
		fin, err := os.Open(inputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if err = fin.Close(); err != nil {
				log.Fatal(err)
			}
		}()
		pagesize := os.Getpagesize()
		reader = bufio.NewReaderSize(fin, pagesize)
	}

	signFileData, err := os.ReadFile(signFile)
	if err != nil {
		return false, fmt.Errorf("failed to read sign file: %w", err)
	}
	log.Debugf("signature file read")

	signatureBlock, rest := pem.Decode(signFileData)
	if signatureBlock == nil {
		return false, fmt.Errorf("failed to extract signature from signature file")
	}
	log.Debugf("signature decoded")
	signerCertificateBlock, rest := pem.Decode(rest)
	if signerCertificateBlock == nil {
		return false, fmt.Errorf("failed to extract signer's certificate from signature file")
	}
	log.Debugf("signer certificate decoded")
	signerCertificate, err := x509.ParseCertificate(signerCertificateBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse signer certificate: %w", err)
	}
	log.Debugf("signer certificate parsed")

	caFileData, err := os.ReadFile(caFile)
	if err != nil {
		return false, fmt.Errorf("failed to read CA file: %w", err)
	}

	caBlock, _ := pem.Decode(caFileData)
	if caBlock == nil {
		return false, fmt.Errorf("failed decode CA file: %w", err)
	}
	log.Debugf("CA certificate decoded")

	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	log.Debugf("CA certificate parsed")

	return VerifySignature(reader, signatureBlock.Bytes, signerCertificate, caCertificate, hashAlgo)
}

func ListYubiKeys() error {

	log.Debugf("enumerating piv cards")
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("ListYubiKeys(): %w", err)
	}

	if len(cards) == 0 {
		fmt.Printf("no cards found")
		return nil
	}
	log.Debugf("%d cards found", len(cards))

	idx := 0
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			fmt.Printf("%d: %s\n", idx, card)
			idx++
		}
	}
	log.Debugf("%d YubiKey cards found", idx)
	return nil
}

func YubiSign(cardIndex int, pinCode string, hashAlgo crypto.Hash, input *bufio.Reader, output *bufio.Writer) error {
	log.Debugf("enumerating piv cards")
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if len(cards) == 0 {
		return fmt.Errorf("YubiKey is required for signing")
	}

	idx := 0
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if idx != cardIndex {
				idx++
				continue
			}
			if yk, err = piv.Open(card); err != nil {
				return fmt.Errorf("error opening yubikey piv applet")
			}
			break
		}
	}
	if yk == nil {
		if idx < cardIndex+1 {
			return fmt.Errorf("no YubiKey with index %d", cardIndex)
		}

		return fmt.Errorf("YubiKey is required for signing")
	}

	log.Debugf("obtaining YubiKey signing certificate")
	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return fmt.Errorf("failed to get signature certificate: %w", err)
	}

	auth := piv.KeyAuth{PIN: pinCode}

	log.Debugf("obtaining private key")
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return fmt.Errorf("failed to get signature key: %w", err)
	}

	log.Debugf("obtaining crypto.Signer interface")
	if _, ok := priv.(crypto.Signer); !ok {
		return fmt.Errorf("failed to get Signer interface on a private key: %w", err)
	}
	signer := priv.(crypto.Signer)

	log.Debugf("generating data digest (%v)", hashAlgo)

	var hasher hash.Hash
	switch hashAlgo {
	case crypto.SHA1:
		hasher = sha1.New()
	case crypto.SHA256:
		hasher = sha256.New()
	case crypto.SHA512:
		hasher = sha512.New()
	default:
		return fmt.Errorf("unsupported hashing algorithm: %v", hashAlgo)
	}
	_, err = io.Copy(hasher, input)
	if err != nil {
		return fmt.Errorf("failed to hash input data: %w", err)
	}
	digest := hasher.Sum(nil)

	log.Debugf("signing input data digest using YubiKey")
	signature, err := signer.Sign(rand.Reader, digest, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}
	log.Infof("input data digest signed")

	block := &pem.Block{
		Type:    "SIGNATURE",
		Headers: map[string]string{},
		Bytes:   signature,
	}

	err = pem.Encode(output, block)
	if err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	block = &pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{},
		Bytes:   cert.Raw,
	}
	err = pem.Encode(output, block)
	if err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	output.Flush()
	return nil
}

func SignWrapper(cardIndex int, pinCode string, hashAlgo crypto.Hash, inputFile, outputFile string) error {

	var reader *bufio.Reader
	if inputFile == "-" {
		log.Debugf("reading from standard input")
		reader = bufio.NewReader(os.Stdin)
	} else {
		log.Debugf("reading from %s", inputFile)
		fin, err := os.Open(inputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if err = fin.Close(); err != nil {
				log.Fatal(err)
			}
		}()
		pagesize := os.Getpagesize()
		reader = bufio.NewReaderSize(fin, pagesize)
	}

	var writer *bufio.Writer
	if outputFile == "-" {
		log.Debugf("writing to standard output")
		writer = bufio.NewWriter(os.Stdout)
	} else {
		log.Debugf("writing to %s", outputFile)
		fout, err := os.Create(outputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if err = fout.Close(); err != nil {
				log.Fatal(err)
			}
		}()
		writer = bufio.NewWriter(fout)
	}

	if pinCode == "-" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Card PIN[123456]: ")
		pinCode, _ = reader.ReadString('\n')
		pinCode = strings.Trim(pinCode, " \n")
		if pinCode == "" {
			pinCode = "123456"
		}
	}

	return YubiSign(cardIndex, pinCode, hashAlgo, reader, writer)
}

func main() {
	var verbose bool
	var cardIndex int
	var inputFile, outputFile, pinCode string
	var signFile, caFile string

	log.SetLevel(logrus.InfoLevel)

	var rootCmd = &cobra.Command{}
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "list available YubiKeys",
		Run: func(cmd *cobra.Command, args []string) {
			if verbose {
				log.SetLevel(logrus.DebugLevel)
			}
			err := ListYubiKeys()
			if err != nil {
				log.Errorf("failed to list YubiKeys")
				os.Exit(1)
			}
		},
	}

	var signCmd = &cobra.Command{
		Use:   "sign",
		Short: "sign the data",
		Long: `Signs input data using YubiKey signing slot (0x9c)

yubisigner sign -i data.txt -o data.sig -p PIN

will generate data.sig file with pem format encoded signature and signer's certificate
`,

		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if verbose {
				log.SetLevel(logrus.DebugLevel)
			}

			err := SignWrapper(cardIndex, pinCode, crypto.SHA512, inputFile, outputFile)
			if err != nil {
				log.Errorf("signing error: %v", err)
				os.Exit(1)
			}
		},
	}
	// TODO: configurable hash algorithm
	signCmd.Flags().IntVarP(&cardIndex, "card", "c", 0, "YubiKey index")
	signCmd.Flags().StringVarP(&pinCode, "pin", "p", "-", "YubiKey PIN code")
	signCmd.Flags().StringVarP(&inputFile, "input", "i", "-", "file, stdin will be used if omitted")
	signCmd.Flags().StringVarP(&outputFile, "output", "o", "-", "file, stdout will be used if omitted")

	var verifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "verify the signature",
		Long: `Verifies the input data signature using provided Certificate authority file

yubisigner verify -i data.txt -s data.sig --CA CA.crt

will check the signature and issuer certificate
`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if verbose {
				log.SetLevel(logrus.DebugLevel)
			}

			verified, err := VerifySignatureWrapper(inputFile, signFile, caFile, crypto.SHA512)
			if err != nil {
				log.Errorf("verification error: %v", err)
				os.Exit(2)
			}
			if verified {
				fmt.Printf("Verified OK\n")
				os.Exit(0)
			} else {
				fmt.Printf("Verification failure\n")
				os.Exit(1)
			}
		},
	}

	// TODO: configurable hash algorithm
	verifyCmd.Flags().StringVarP(&inputFile, "input", "i", "-", "data file, stdin will be used if omitted")
	verifyCmd.Flags().StringVarP(&signFile, "signature", "s", "-", "signature file in pem format")
	verifyCmd.Flags().StringVarP(&caFile, "CA", "C", "-", "Certificate Authority Certificate in pem format")
	verifyCmd.MarkFlagRequired("input")
	verifyCmd.MarkFlagRequired("signature")
	verifyCmd.MarkFlagRequired("CA")

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
