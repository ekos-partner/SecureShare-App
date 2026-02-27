package main

import (
	"bufio"
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
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	defaultAPIURL = "http://localhost:3000"
)

const (
	keySize    = 32
	ivSize     = 12
	saltSize   = 16
	iterations = 100000
)

type CreateSecretRequest struct {
	EncryptedData   string  `json:"encryptedData"`
	PasswordHash    *string `json:"passwordHash,omitempty"`
	Salt            *string `json:"salt,omitempty"`
	ExpirationHours int     `json:"expirationHours"`
	ViewLimit       int     `json:"viewLimit"`
	PowNonce        string  `json:"powNonce,omitempty"`
	PowSalt         string  `json:"powSalt,omitempty"`
}

type PoWChallenge struct {
	Resource   string `json:"resource"`
	Salt       string `json:"salt"`
	Difficulty int    `json:"difficulty"`
}

func solvePoW(resource string, salt string, difficulty int) string {
	fmt.Printf("Solving security challenge (difficulty: %d)... ", difficulty)
	start := time.Now()
	targetPrefix := strings.Repeat("0", difficulty)
	var nonce int64 = 0

	for {
		header := fmt.Sprintf("1:%d:%s:%s:%d", difficulty, resource, salt, nonce)
		hash := sha256.Sum256([]byte(header))

		// Convert hash to binary string
		var binary strings.Builder
		for _, b := range hash {
			binary.WriteString(fmt.Sprintf("%08b", b))
		}

		if strings.HasPrefix(binary.String(), targetPrefix) {
			fmt.Printf("done in %v\n", time.Since(start).Round(time.Millisecond))
			return fmt.Sprintf("%d", nonce)
		}
		nonce++
	}
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
	// Initialize default API URL from environment variable if available
	if envURL := os.Getenv("SECURESHARE_URL"); envURL != "" {
		defaultAPIURL = envURL
	}

	// Simple subcommand detection
	if len(os.Args) > 1 {
		if os.Args[1] == "get" {
			handleGet()
			return
		}
		if os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
			printGeneralUsage()
			return
		}
		// If it's 'create', skip the word and pass the rest
		if os.Args[1] == "create" {
			handleCreate(os.Args[2:])
			return
		}
	}

	// Check for piped input or arguments
	stat, err := os.Stdin.Stat()
	isPiped := err == nil && (stat.Mode()&os.ModeCharDevice) == 0

	if len(os.Args) < 2 && !isPiped {
		printGeneralUsage()
		return
	}

	// Default: handle as create with all original arguments
	handleCreate(os.Args[1:])
}

func printGeneralUsage() {
	binaryName := "secureshare-cli"
	examplePrefix := "./"
	if runtime.GOOS == "windows" {
		binaryName = "secureshare-cli.exe"
		examplePrefix = ".\\"
	}

	fmt.Printf("SecureShare CLI - End-to-End Encrypted Secret Sharing (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("\nUsage:")
	fmt.Printf("  %s%s create [options] [secret]  - Create a new secret\n", examplePrefix, binaryName)
	fmt.Printf("  %s%s get <url> [options]        - Retrieve and decrypt a secret\n", examplePrefix, binaryName)
	fmt.Println("\nEnvironment Variables:")
	fmt.Println("  SECURESHARE_URL  - Set default server URL (e.g., https://secureshare.example.com)")
	fmt.Println("\nExamples:")
	fmt.Printf("  %s%s -url https://secureshare.example.com \"Hello World\"\n", examplePrefix, binaryName)
	fmt.Printf("  echo \"Secret\" | %s%s -url https://secureshare.example.com -expire 1\n", examplePrefix, binaryName)
	fmt.Printf("  %s%s get https://secureshare.example.com/s/uuid#key\n", examplePrefix, binaryName)
	fmt.Printf("\nRun '%s%s create --help' or '%s%s get --help' for more details.\n", examplePrefix, binaryName, examplePrefix, binaryName)
}

func handleGet() {
	getFlags := flag.NewFlagSet("get", flag.ExitOnError)
	password := getFlags.String("password", "", "Password for the secret (if protected)")
	getFlags.Usage = func() {
		fmt.Println("Usage: secureshare-cli get <url> [options]")
		getFlags.PrintDefaults()
	}

	// Custom parsing to allow flags anywhere (e.g., after the URL)
	var rawURL string
	args := os.Args[2:]
	var flagsToParse []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagsToParse = append(flagsToParse, args[i])
			// If it's a flag that takes a value and there is a next arg
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagsToParse = append(flagsToParse, args[i+1])
				i++
			}
		} else if rawURL == "" {
			rawURL = args[i]
		}
	}
	getFlags.Parse(flagsToParse)

	if rawURL == "" {
		fmt.Println("Error: Missing secret URL")
		getFlags.Usage()
		os.Exit(1)
	}

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
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			pw = strings.TrimSpace(input)
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
	
	// Custom parsing to allow flags anywhere
	var secretParts []string
	var flagsToParse []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagsToParse = append(flagsToParse, args[i])
			// If it's a flag that takes a value and there is a next arg
			// All our flags (url, expire, views, password) take values
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagsToParse = append(flagsToParse, args[i+1])
				i++
			}
		} else {
			secretParts = append(secretParts, args[i])
		}
	}
	createFlags.Parse(flagsToParse)

	// Normalize URL by removing trailing slash
	cleanAPIURL := strings.TrimSuffix(*apiURL, "/")

	// Read secret from stdin or arguments
	var secretContent []byte
	if len(secretParts) > 0 {
		secretContent = []byte(strings.Join(secretParts, " "))
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

	// 3. Solve PoW Challenge
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	challengeResp, err := client.Get(cleanAPIURL + "/api/pow/challenge")
	failOnError(err, "fetching security challenge")
	defer challengeResp.Body.Close()

	var challenge PoWChallenge
	err = json.NewDecoder(challengeResp.Body).Decode(&challenge)
	failOnError(err, "decoding security challenge")

	nonce := solvePoW(challenge.Resource, challenge.Salt, challenge.Difficulty)

	// 4. Send to API
	reqBody := CreateSecretRequest{
		EncryptedData:   encryptedData,
		PasswordHash:    passwordHashBase64,
		Salt:            saltBase64,
		ExpirationHours: *expiration,
		ViewLimit:       *views,
		PowNonce:        nonce,
		PowSalt:         challenge.Salt,
	}

	jsonData, err := json.Marshal(reqBody)
	failOnError(err, "marshaling JSON")

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
