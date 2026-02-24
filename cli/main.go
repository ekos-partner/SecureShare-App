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

type GetSecretResponse struct {
	EncryptedData string  `json:"encryptedData"`
	HasPassword   bool    `json:"hasPassword"`
	Salt          *string `json:"salt,omitempty"`
}

type BurnSecretRequest struct {
	PasswordHash *string `json:"passwordHash,omitempty"`
}

// Helper function to display errors and exit
func failOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "get":
			handleGet()
			return
		case "create":
			handleCreate(os.Args[2:])
			return
		case "help", "-h", "--help":
			printGeneralUsage()
			return
		}
	}

	// Default to create for backward compatibility or if no subcommand is matched
	// but flags are provided (e.g., secureshare-cli -url ...)
	args := os.Args[1:]
	handleCreate(args)
}

func printGeneralUsage() {
	fmt.Println("SecureShare CLI - End-to-End Encrypted Secret Sharing")
	fmt.Println("\nUsage:")
	fmt.Println("  secureshare-cli create [options] [secret]  - Create a new secret")
	fmt.Println("  secureshare-cli get <url> [options]        - Retrieve and decrypt a secret")
	fmt.Println("\nExamples:")
	fmt.Println("  secureshare-cli \"Hello World\"")
	fmt.Println("  echo \"Secret\" | secureshare-cli -expire 1")
	fmt.Println("  secureshare-cli get https://...#key")
	fmt.Println("\nRun 'secureshare-cli create --help' or 'secureshare-cli get --help' for more details.")
}

func handleGet() {
	getFlags := flag.NewFlagSet("get", flag.ExitOnError)
	password := getFlags.String("password", "", "Password for the secret (if protected)")
	getFlags.Usage = func() {
		fmt.Println("Usage: secureshare-cli get <url> [options]")
		getFlags.PrintDefaults()
	}
	getFlags.Parse(os.Args[2:])

	if getFlags.NArg() < 1 {
		fmt.Println("Usage: secureshare-cli get <url> [-password <pw>]")
		os.Exit(1)
	}

	rawURL := getFlags.Arg(0)
	// Parse URL: https://domain.com/s/uuid#key
	parts := strings.Split(rawURL, "#")
	if len(parts) < 2 {
		fmt.Println("Error: Invalid URL format. Missing decryption key (fragment after #)")
		os.Exit(1)
	}
	keyBase64 := parts[1]
	
	// Extract ID from path
	urlParts := strings.Split(parts[0], "/")
	id := urlParts[len(urlParts)-1]
	if id == "" && len(urlParts) > 1 {
		id = urlParts[len(urlParts)-2]
	}

	// Determine API URL from the provided link
	apiURL := strings.Join(urlParts[:3], "/") // http(s)://domain.com

	client := &http.Client{Timeout: 15 * time.Second}

	// 1. Fetch Metadata
	resp, err := client.Get(apiURL + "/api/secrets/" + id)
	failOnError(err, "fetching secret metadata")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error: Secret not found or expired (%d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var meta GetSecretResponse
	err = json.NewDecoder(resp.Body).Decode(&meta)
	failOnError(err, "decoding metadata")

	// 2. Handle Password and Burn
	var encryptionKey []byte
	var passwordHashBase64 *string

	if meta.HasPassword {
		pw := *password
		if pw == "" {
			fmt.Print("Secret is password protected. Enter password: ")
			fmt.Scanln(&pw)
		}

		if meta.Salt == nil {
			fmt.Println("Error: Missing salt for password-protected secret")
			os.Exit(1)
		}
		salt, err := base64.StdEncoding.DecodeString(*meta.Salt)
		failOnError(err, "decoding salt")

		combinedSecret := keyBase64 + pw
		encryptionKey = pbkdf2.Key([]byte(combinedSecret), salt, iterations, keySize, sha256.New)

		pwHash := pbkdf2.Key([]byte(pw), salt, iterations, 32, sha256.New)
		ph := base64.StdEncoding.EncodeToString(pwHash)
		passwordHashBase64 = &ph
	} else {
		key, err := base64.StdEncoding.DecodeString(keyBase64)
		failOnError(err, "decoding key from URL")
		encryptionKey = key
	}

	// Burn the secret
	burnReq := BurnSecretRequest{PasswordHash: passwordHashBase64}
	burnData, _ := json.Marshal(burnReq)
	burnResp, err := client.Post(apiURL+"/api/secrets/"+id+"/burn", "application/json", bytes.NewBuffer(burnData))
	failOnError(err, "burning secret")
	defer burnResp.Body.Close()

	if burnResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(burnResp.Body)
		fmt.Fprintf(os.Stderr, "Error: Failed to access secret (%d): %s\n", burnResp.StatusCode, string(body))
		os.Exit(1)
	}

	// 3. Decrypt
	dataParts := strings.Split(meta.EncryptedData, ":")
	if len(dataParts) != 2 {
		fmt.Println("Error: Invalid encrypted data format from server")
		os.Exit(1)
	}

	iv, err := base64.StdEncoding.DecodeString(dataParts[0])
	failOnError(err, "decoding IV")
	ciphertext, err := base64.StdEncoding.DecodeString(dataParts[1])
	failOnError(err, "decoding ciphertext")

	block, err := aes.NewCipher(encryptionKey)
	failOnError(err, "creating cipher block")

	aesgcm, err := cipher.NewGCM(block)
	failOnError(err, "creating GCM")

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	failOnError(err, "decrypting data")

	fmt.Println(string(plaintext))
}

func handleCreate(args []string) {
	createFlags := flag.NewFlagSet("create", flag.ExitOnError)
	apiURL := createFlags.String("url", defaultAPIURL, "API URL of the SecureShare instance")
	expiration := createFlags.Int("expire", 24, "Expiration time in hours (1-168)")
	views := createFlags.Int("views", 1, "View limit (1-10)")
	password := createFlags.String("password", "", "Optional password for extra protection")
	
	createFlags.Usage = func() {
		fmt.Println("Usage: secureshare-cli [create] [options] [secret]")
		fmt.Println("       echo \"secret\" | secureshare-cli [create] [options]")
		createFlags.PrintDefaults()
	}
	
	createFlags.Parse(args)

	// Normalize URL by removing trailing slash
	cleanAPIURL := strings.TrimSuffix(*apiURL, "/")

	// Read secret from stdin or arguments
	var secretContent []byte
	if len(createFlags.Args()) > 0 {
		secretContent = []byte(strings.Join(createFlags.Args(), " "))
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
			createFlags.Usage()
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
