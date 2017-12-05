////////////////////////////////////////////////////////////////////////////////
//
//  File           : swallet443.go
//  Description    : This is the implementaiton file for the swallet password
//                   wallet program program.  See assignment details.
//
//  Collaborators  : **TODO**: FILL ME IN
//  Last Modified  : **TODO**: FILL ME IN
//

// Package statement
package main

// Imports
import ( 
	"fmt"
	"os"
	"time"
	"strings"
	"math/rand"
	"github.com/pborman/getopt"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha1"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"io"
	"io/ioutil"
	"strconv"
	"errors"
	
	// There will likely be several mode APIs you need
)
import crand "crypto/rand"

// Type definition  ** YOU WILL NEED TO ADD TO THESE **

// A single password
type walletEntry struct {
	password []byte    // Should be exactly 32 bytes with zero right padding
	salt []byte        // Should be exactly 16 bytes 
	comment []byte     // Should be exactly 128 bytes with zero right padding
}					   // Comment cannot be null padded. Inconsistent with schema

// The wallet as a whole
type wallet struct {
	filename string
	masterPassword []byte   // Should be exactly 32 bytes with zero right padding
	passwords []walletEntry
	genNum int 
}

// Global data
var usageText string = `USAGE: swallet443 [-h] [-v] <wallet-file> [create|add|del|show|chpw|reset|list] <password> <comment>

where:
    -h - help mode (display this message)
    -v - enable verbose output

    <wallet-file> - wallet file to manage
	[create|add|del|show|chpw] - is a command to execute, where
	<password> - password to be added or removed
	<comment> - comment associated with a password

     create - create a new wallet file
     add - adds a password to the wallet
     del - deletes a password from the wallet
     show - show a password in the wallet
     chpw - changes the password for an entry in the wallet
     reset - changes the password for the wallet
     list - list the entries in the wallet (without passwords)`

var verbose bool = true

// You may want to create more global variables
const PASSWORD_BYTE_SIZE int = 32
const COMMENT_BYTE_SIZE int = 128
const SALT_BYTE_SIZE int = 16
const ENTRY_BYTE_SIZE int = 32

//
// Functions

// Up to you to decide which functions you want to add

////////////////////////////////////////////////////////////////////////////////
//
// Function     : walletUsage
// Description  : This function prints out the wallet help
//
// Inputs       : none
// Outputs      : none

func walletUsage() {
	fmt.Fprintf(os.Stderr, "%s\n\n", usageText)
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : createWallet
// Description  : This function creates a wallet if it does not exist
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func createWallet(filename string) *wallet {

	// Setup the wallet
	var wal443 wallet 
	wal443.filename = filename
	wal443.masterPassword = make([]byte, 32, 32) // You need to take it from here
	wal443.genNum = 0

	//temp
	wal443.masterPassword = []byte("12345")

	// Return the wall
	return &wal443
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : loadWallet
// Description  : This function loads an existing wallet
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func loadWallet(filename string) *wallet {

	// Setup the wallet
	var wal443 wallet 
	// DO THE LOADING HERE
	wal443.filename = filename

	// Return the wall	
	return &wal443	
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : saveWallet
// Description  : This function save a wallet to the file specified
//
// Inputs       : walletFile - the name of the wallet file
// Outputs      : true if successful test, false if failure

func (wal443 wallet) saveWallet() bool {

	wal443.genNum++
	data := time.Now().Format("2006-01-02 15:04:05") + "\x7c" + strconv.Itoa(wal443.genNum) + "\n"
	buffer := bytes.NewBuffer([]byte(data))
	
	hashedPassword := getSHA1Hash(wal443.masterPassword)
	walletKey := truncateStringToBytes(hashedPassword, 16)
	
	for index, walEntry := range wal443.passwords {
		
		// Entry : PADDING IS INCONSISTENT WITH SCHEMA
		/*
		entryBytes := []byte("Entry " + strconv.Itoa(index + 1))
		buff := bytes.NewBuffer(entryBytes)		
		if buff.Len() < ENTRY_BYTE_SIZE { 
			padding := ENTRY_BYTE_SIZE - buff.Len()
			for i := 0; i < padding ; i++ {
				_, err := buff.WriteString("\x00")
				check(err)
			} 
			entryString = buff.String()
		} else {
			entryString = truncateStringToBytes(entryBytes, ENTRY_BYTE_SIZE)
		}
		*/
		entryString := "Entry " + strconv.Itoa(index + 1)
		buff := bytes.NewBuffer([]byte(entryString))
		if buff.Len() > ENTRY_BYTE_SIZE { buff.Truncate(ENTRY_BYTE_SIZE) }
		entryString = buff.String()


		// AES Encryption
		aesPassword, pass_err := aes_encrypt(walletKey, string(walEntry.salt) + "||" + string(walEntry.password))
		check(pass_err)
		// aesPassword := string(walEntry.salt) + "||" + string(walEntry.password)
		// aesBase64Password := base64.URLEncoding.EncodeToString([]byte(aesPassword))

		data := entryString + "||" + aesPassword + "||" + string(walEntry.comment) + "\n"
		fmt.Println(data)

		_, err := buffer.WriteString(data)
		check(err)
		
	}

	hmac := createMAC(buffer.Bytes(), walletKey)
	hmacString := base64.URLEncoding.EncodeToString(hmac)
	buffer.WriteString(hmacString + "\n")
	err := ioutil.WriteFile(wal443.filename + ".txt", buffer.Bytes(), 0644)
	check(err)

	// Return successfully
	return true
}
func (wal443 wallet) showPassword() bool{

    fmt.Print("Enter Password Number: ")
    var input string
    fmt.Scanln(&input)
    fmt.Print(input)

	entry, err := strconv.Atoi(input)
	if err != nil {
		fmt.Print("Error")
	}
	entry -= 1 //zero indexed
	//look up from the password array 

	encrpytedPw := wal443.passwords[entry].password
	
	result, err := aes_decrypt(wal443.masterPassword, string(encrpytedPw))
	if err != nil {
		fmt.Print("Error")
	}

	fmt.Printf("Password Entry %d is %s", entry, result)

	return true
}	
func (wal443 wallet) listPassword() bool{

	for i := 0; i < len(wal443.passwords); i++ {

		fmt.Printf("Password Entry %d Comment: %s", i, wal443.passwords[i].comment)
	}

	return true
}
func (wal443 wallet) changePassword() bool{
	
	fmt.Print("Enter Password Number: ")
    var input string
    fmt.Scanln(&input)
    fmt.Print(input)

    entry, err := strconv.Atoi(input)
	if err != nil {
		fmt.Print("Error")
	}
	entry -= 1 //zero indexed

	fmt.Print("Enter New Password: ")
    var newpw string
    fmt.Scanln(&newpw)
    fmt.Print(newpw)

    //perhaps the UI interface needs to be called here
    
    wal443.passwords[entry].password = []byte(newpw)

	return true
}	
func (wal443 wallet) resetPassword() bool{

	fmt.Print("helloWorld")

	return true
}
////////////////////////////////////////////////////////////////////////////////
//
// Function     : processWalletCommand
// Description  : This is the main processing function for the wallet
//
// Inputs       : walletFile - the name of the wallet file
//                command - the command to execute
// Outputs      : true if successful test, false if failure

func (wal443 wallet) processWalletCommand(command string, password string, comment string) (bool, wallet) {

	// Process the command 
	switch command {
	case "add":
		wal443 = wal443.addPassword(password, comment)
		break

	case "del":
		wal443.deletePassword(password)
		break
		
	case "show":
		wal443.showPassword()
		
	case "chpw":
		wal443.changePassword()

	case "reset":
		wal443.resetPassword()		
	case "list":
		wal443.listPassword()		
	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
		return false, wal443
	}

	// Return sucessfull
	return true, wal443
}

func (wal443 wallet) addPassword(password string, comment string) wallet{
	
	var walEntry walletEntry
	buff := bytes.NewBuffer([]byte(password))
	
	// Password
	if buff.Len() < PASSWORD_BYTE_SIZE { 
		padding := PASSWORD_BYTE_SIZE - buff.Len()
		for i := 0; i < padding ; i++ {
			_, err := buff.WriteString("\x00")
			check(err)
		} 
	}
	walEntry.password = buff.Bytes()

	// Comment : PADDING IS INCONSISTENT WITH SCHEMA
	/*
	buff = bytes.NewBuffer([]byte(comment))
	if buff.Len() < COMMENT_BYTE_SIZE { 
		padding := COMMENT_BYTE_SIZE - buff.Len()
		for i := 0; i < padding ; i++ {
			_, err := buff.WriteString("\x00")
			check(err)
		} 
	}*/
	buff = bytes.NewBuffer([]byte(comment))
	if buff.Len() > COMMENT_BYTE_SIZE { buff.Truncate(COMMENT_BYTE_SIZE) }
	walEntry.comment = buff.Bytes()
	
	// Salt
	saltBytes := make([]byte, SALT_BYTE_SIZE)
    if _, err := rand.Read(saltBytes); err != nil {
        panic(err)
	}
	// s := fmt.Sprintf("%X", saltBytes)
	walEntry.salt = saltBytes
	
	// Add wallEntry to Passwords
	wal443.passwords = append(wal443.passwords, walEntry)
	return wal443
}

func (wal443 wallet) deletePassword(password string) {
	
	buff := bytes.NewBuffer([]byte(password))
	
	// Password
	if buff.Len() < PASSWORD_BYTE_SIZE { 
		padding := PASSWORD_BYTE_SIZE - buff.Len()
		for i := 0; i < padding ; i++ {
			_, err := buff.WriteString("\x00")
			check(err)
		} 
	}
	delPassword := buff.Bytes()

	// remove walletEntry associated with password
	for index, walEntry := range wal443.passwords {
		if bytes.Equal(walEntry.password, delPassword) {
			wal443.passwords = append(wal443.passwords[:index], wal443.passwords[index + 1 :]...)
			break
		}
	}
}
////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the password generator program
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

func main() {

	// Setup options for the program content
	getopt.SetUsage(walletUsage)
	rand.Seed(time.Now().UTC().UnixNano())
	helpflag := getopt.Bool('h', "", "help (this menu)")
	verboseflag := getopt.Bool('v', "", "enable verbose output")

	// Now parse the command line arguments
	err := getopt.Getopt(nil)
	if err != nil {
		// Handle error
		fmt.Fprintln(os.Stderr, err)
		getopt.Usage()
		os.Exit(-1)
	}

	// Process the flags
	fmt.Printf("help flag [%t]\n", *helpflag)
	fmt.Printf("verbose flag [%t]\n", *verboseflag)
	verbose = *verboseflag
	if *helpflag == true {
		getopt.Usage()
		os.Exit(-1)
	}

	// Check the arguments to make sure we have enough, process if OK
	if getopt.NArgs() < 2 {
		fmt.Printf("Not enough arguments for wallet operation.\n")
		getopt.Usage()
		os.Exit(-1)
	}
	fmt.Printf("wallet file [%s]\n", getopt.Arg(0))
	filename := getopt.Arg(0)
	fmt.Printf("command [%s]\n", getopt.Arg(1))
	command := strings.ToLower(getopt.Arg(1))

	fmt.Printf("password [%s]\n", getopt.Arg(2))
	password := strings.ToLower(getopt.Arg(2))

	fmt.Printf("comment [%s]\n", getopt.Arg(3))
	comment := getopt.Arg(3)

	// Now check if we are creating a wallet
	if command == "create" {

		// Create and save the wallet as needed
		wal443 := createWallet(filename)
		if wal443 != nil {
			wal443.saveWallet()
		}

	} else {

		// Load the wallet, then process the command
		wal443 := loadWallet(filename)
		var ok bool
		ok, *wal443 = wal443.processWalletCommand(command, password, comment)
		if wal443 != nil && ok {
			wal443.saveWallet()
		}

	}

	// Return (no return code)
	return
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func truncateStringToBytes(data []byte, numBytes int) []byte {
	
	buff := bytes.NewBuffer([]byte(data))
	if buff.Len() > numBytes { buff.Truncate(numBytes) }// keep first numBytes and discard the rest
	
	if buff.Len() < numBytes { 
		padding := numBytes - buff.Len()
		for i := 0; i < padding ; i++ {
			_, err := buff.WriteString("\x00")
			check(err)
		} 
	}
	fmt.Printf("truncateStringToBytes : %d\n", buff.Len())
	
	return buff.Bytes()
	
}

func getSHA1Hash(data []byte) []byte {
	hasher := sha1.New()
	hasher.Write(data)
	result := hasher.Sum(nil)

	// fmt.Println(data)
	// fmt.Printf("%x\n", result)

	return result
}

// Reference - https://gist.github.com/mickelsonm/e1bf365a149f3fe59119
func aes_encrypt(key []byte, message string) (result string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	check(err)

	//IV is a unique stream that is appended to the beginning of the ciphertext
	cipherText := make([]byte, aes.BlockSize + len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(crand.Reader, iv); err != nil {
		check(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	// returns base64 encoded string
	result = base64.URLEncoding.EncodeToString(cipherText)
	return
}

// Reference - https://gist.github.com/mickelsonm/e1bf365a149f3fe59119
func aes_decrypt(key []byte, encmessage string) (result string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(encmessage)
	check(err)

	block, err := aes.NewCipher(key)
	check(err)

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short")
		check(err)
	}

	//IV is a unique stream that is appended to the beginning of the ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	result = string(cipherText)
	return
}

// Reference - https://golang.org/pkg/crypto/hmac/
// CheckMAC reports whether messageMAC is a valid HMAC tag for message.
func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func createMAC(data, masterkey[] byte) (hMAC []byte) {
	mac := hmac.New(sha256.New, masterkey)
	mac.Write(data)
	hMAC = mac.Sum(nil)
	return
}