package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"

	"github.com/tink-crypto/tink-go-hcvault/v2/integration/hcvault"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func main() {
	const keyURI = "hcvault://localhost:8200/transit/keys/demo-tink"
	client, err := hcvault.NewClient(keyURI, &tls.Config{InsecureSkipVerify: true}, "root")
	if err != nil {
		log.Fatal(err)
	}
	kekAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		log.Fatal(err)
	}
	// Generate a new keyset handle for the primitive we want to use.
	newHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	// Choose some associated data. This is the context in which the keyset will be used.
	keysetAssociatedData := []byte("keyset encryption example")

	// Encrypt the keyset with the KEK AEAD and the associated data.
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = newHandle.WriteWithAssociatedData(writer, kekAEAD, keysetAssociatedData)
	if err != nil {
		log.Fatal(err)
	}
	encryptedKeyset := buf.Bytes()

	// The encrypted keyset can now be stored.

	// To use the primitive, we first need to decrypt the keyset. We use the same
	// KEK AEAD and the same associated data that we used to encrypt it.
	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	handle, err := keyset.ReadWithAssociatedData(reader, kekAEAD, keysetAssociatedData)
	if err != nil {
		log.Fatal(err)
	}

	// Get the primitive.
	primitive, err := aead.New(handle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive.
	plaintext := []byte("message")
	associatedData := []byte("example encryption")
	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(decrypted))
	// Output: message

}
