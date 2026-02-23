package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultAPIURL = "http://localhost:3000"
	keySize       = 32
	ivSize        = 12
	saltSize      = 16
	iterations    = 100000
)

type CreateSecretRequest struct {
	EncryptedData   string  `json:"encryptedData"`
	PasswordHash    *string `json:"passwordHash,omitempty"`
	Salt            *string `json:"salt,omitempty"`
	ExpirationHours int     `json:"expirationHours"`
	ViewLimit       int     `json:"viewLimit"`
}

type CreateSecretResponse struct {
	ID string `json:"id"`
}

func main() {
	apiURL := flag.String("url", defaultAPIURL, "API URL of the SecureShare instance")
	expiration := flag.Int("expire", 24, "Expiration time in hours (1-168)")
	views := flag.Int("views", 1, "View limit (1-10)")
	password := flag.String("password", "", "Optional password for extra protection")
	flag.Parse()

	// Read secret from stdin or arguments
	var secretContent []byte
	if len(flag.Args()) > 0 {
		secretContent = []byte(strings.Join(flag.Args(), " "))
	} else {
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			var err error
			secretContent, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Usage: echo 'secret' | secureshare-cli [options]")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	if len(secretContent) == 0 {
		fmt.Println("Error: Secret content is empty")
		os.Exit(1)
	}

	// 1. Generate Key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	keyBase64 := base64.StdEncoding.EncodeToString(key)

	// 2. Encrypt Content
	var encryptionKey []byte
	var saltBase64 *string
	var passwordHashBase64 *string

	if *password != "" {
		// Password-based encryption logic matching the frontend
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			panic(err)
		}
		s := base64.StdEncoding.EncodeToString(salt)
		saltBase64 = &s

		// Derive key: PBKDF2(key + password, salt)
		combinedSecret := keyBase64 + *password
		encryptionKey = pbkdf2.Key([]byte(combinedSecret), salt, iterations, keySize, sha256.New)

		// Generate password hash for server verification
		// Hash(password + salt)
		pwHash := sha256.Sum256([]byte(*password + *saltBase64))
		ph := base64.StdEncoding.EncodeToString(pwHash[:])
		passwordHashBase64 = &ph
	} else {
		encryptionKey = key
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}

	ciphertext := aesgcm.Seal(nil, iv, secretContent, nil)

	// Format: IV:Ciphertext
	ivBase64 := base64.StdEncoding.EncodeToString(iv)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	encryptedData := ivBase64 + ":" + ciphertextBase64

	// 3. Send to API
	reqBody := CreateSecretRequest{
		EncryptedData:   encryptedData,
		PasswordHash:    passwordHashBase64,
		Salt:            saltBase64,
		ExpirationHours: *expiration,
		ViewLimit:       *views,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(*apiURL+"/api/secrets", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Server error (%d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var result CreateSecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding response: %v\n", err)
		os.Exit(1)
	}

	// 4. Output Link
	// The link format is: <URL>/secret/<ID>#<KEY>
	// Note: The key is in the URL fragment, so it's never sent to the server.
	shareLink := fmt.Sprintf("%s/secret/%s#%s", *apiURL, result.ID, keyBase64)
	fmt.Println(shareLink)
}
