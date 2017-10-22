package vault

import (
	"crypto/rand"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"os"
)

// New returns a new vault, pass a random salt for deriving a key. Note that the
// same salt should be passed in to decrypt data later
func New(salt []byte) Vault {
	return Vault{Salt: salt}
}

// Vault is used to store information for the encryption and decryption process.
// Namely, a salt for generating a key, the key itself.
type Vault struct {
	Salt []byte
	key  []byte
}

// Unlock unlocks the vault by generating a key used to decrypt or encrypt data
func (v *Vault) Unlock(password string) error {
	key, err := scrypt.Key([]byte(password), v.Salt, 16384, 8, 1, 32)
	if err != nil {
		return err
	}
	v.key = key
	return nil
}

// Encrypt data
func (v Vault) Encrypt(data []byte) ([]byte, error) {
	if len(v.key) == 0 {
		return []byte{}, errors.New("Must unlock vault before encrypting data")
	}
	var secretKey [32]byte
	copy(secretKey[:], v.key)
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return []byte{}, errors.Wrap(err, "Error during nonce generation")
	}
	encrypted := secretbox.Seal(nonce[:], data, &nonce, &secretKey)
	return encrypted, nil
}

// Decrypt encrypted data
func (v Vault) Decrypt(encrypted []byte) ([]byte, error) {
	if len(v.key) == 0 {
		return []byte{}, errors.New("Must unlock vault before decrypting data")
	}
	var secretKey [32]byte
	copy(secretKey[:], v.key)
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secretKey)
	if !ok {
		return []byte{}, errors.New("Error decrypting data, wrong password?")
	}
	return decrypted, nil
}

// DecryptFile helper method for decrypting data from a file
func (v Vault) DecryptFile(filePath string) ([]byte, error) {
	encrypted, err := ioutil.ReadFile(filePath)
	if err != nil {
		return []byte{}, errors.Wrap(err, "Error reading file")
	}
	return v.Decrypt(encrypted)
}

// EncryptToFile helper method for encrypting data into a file
func (v Vault) EncryptToFile(data []byte, filePath string) error {
	encrypted, err := v.Encrypt(data)
	if err != nil {
		return errors.Wrap(err, "Error during encrypting of data")
	}

	file, err := os.Create(filePath)
	if err != nil {
		return errors.Wrap(err, "Error during file opening")
	}
	_, err = file.Write(encrypted)
	if err != nil {
		return errors.Wrap(err, "Error during file writing")
	}
	return file.Close()
}
