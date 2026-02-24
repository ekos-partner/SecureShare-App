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
	"time"

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

// Helper function to display errors and exit
func failOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
		os.Exit(1)
	}
}

func main() {
	apiURL := flag.String("url", defaultAPIURL, "API URL of the SecureShare instance")
	expiration := flag.Int("expire", 24, "Expiration time in hours (1-168)")
	views := flag.Int("views", 1, "View limit (1-10)")
	password := flag.String("password", "", "Optional password for extra protection")
	flag.Parse()

	// Normalize URL by removing trailing slash
	cleanAPIURL := strings.TrimSuffix(*apiURL, "/")

	// Read secret from stdin or arguments
	var secretContent []byte
	if len(flag.Args()) > 0 {
		secretContent = []byte(strings.Join(flag.Args(), " "))
	} else {
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			var err error
			rawContent, err := io.ReadAll(os.Stdin)
			failOnError(err, "reading from stdin")
			// Trim whitespace (e.g., newline from echo)
			secretContent = bytes.TrimSpace(rawContent)
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
	_, err := rand.Read(key)
	failOnError(err, "generating random key")
	keyBase64 := base64.StdEncoding.EncodeToString(key)

	// 2. Encrypt Content
	var encryptionKey []byte
	var saltBase64 *string
	var passwordHashBase64 *string

	if *password != "" {
		salt := make([]byte, saltSize)
		_, err := rand.Read(salt)
		failOnError(err, "generating salt")
		
		s := base64.StdEncoding.EncodeToString(salt)
		saltBase64 = &s

		combinedSecret := keyBase64 + *password
		encryptionKey = pbkdf2.Key([]byte(combinedSecret), salt, iterations, keySize, sha256.New)

		pwHash := pbkdf2.Key([]byte(*password), salt, iterations, 32, sha256.New)
		ph := base64.StdEncoding.EncodeToString(pwHash)
		passwordHashBase64 = &ph
	} else {
		encryptionKey = key
	}

	block, err := aes.NewCipher(encryptionKey)
	failOnError(err, "creating cipher block")

	aesgcm, err := cipher.NewGCM(block)
	failOnError(err, "creating GCM")

	iv := make([]byte, ivSize)
	_, err = rand.Read(iv)
	failOnError(err, "generating IV")

	ciphertext := aesgcm.Seal(nil, iv, secretContent, nil)

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
	failOnError(err, "marshaling JSON")

	// Use custom HTTP client with timeout
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Post(cleanAPIURL+"/api/secrets", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Server error (%d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var result CreateSecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding response: %v\n", err)
		os.Exit(1)
	}

	// Output the shareable link
	shareLink := fmt.Sprintf("%s/s/%s#%s", cleanAPIURL, result.ID, keyBase64)
	fmt.Println(shareLink)
}
