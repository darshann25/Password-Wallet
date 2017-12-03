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
	//"crypto/hmac"
	//"crypto/sha256"
	"crypto/sha1"
	"encoding/base64"
	"io/ioutil"
	"strconv"
	// There will likely be several mode APIs you need
)

// Type definition  ** YOU WILL NEED TO ADD TO THESE **

// A single password
type walletEntry struct {
	password []byte    // Should be exactly 32 bytes with zero right padding
	salt []byte        // Should be exactly 16 bytes 
	comment []byte     // Should be exactly 128 bytes with zero right padding
}

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
var PASSWORD_BYTE_SIZE int = 32
var COMMENT_BYTE_SIZE int = 128
var SALT_BYTE_SIZE int = 16

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

	// Setup the wallet in the correct form
	//then save to txt file 
	//wallet form 

	data := time.Now().Format("2006-01-02 15:04:05") + "||"+ strconv.Itoa(wal443.genNum) + "\n"
	err := ioutil.WriteFile(wal443.filename + ".txt", []byte(data), 0644)
	check(err)
	
	//for all pwd in wallet.passwords[] append to data entry  32 salt 16 password 16 commetn 128 ; passwords base64 encoded
	truncMastPassword := truncateStringToBytes(wal443.masterPassword, 16)
	walletKey := getSHA1Hash(truncMastPassword)
	fmt.Println(walletKey)
	fmt.Printf("%x\n", walletKey)

	



	
	// masterKey := hmac.New(sha256.New, truncMastPassword) 


	//base64 encoding 
	// data2.Write([]byte(data)); 
	encoder := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	// encoder.Write([]byte(masterKey))
	encoder.Close()

	//join data and data2 
	
	//write to file 


	// ioutil.WriteFile(wal443.filename+".txt", []byte(data2), 0644)

	// Return successfully
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

func (wal443 wallet) processWalletCommand(command string, password string, comment string) bool {

	// Process the command 
	switch command {
	case "add":
		wal443.addPassword(password, comment)
		break

	case "del":
		wal443.deletePassword(password)
		
	case "show":
		// DO SOMETHING HERE
		
	case "chpw":
		// DO SOMETHING HERE
		
	case "reset":
		// DO SOMETHING HERE
		
	case "list":
		// DO SOMETHING HERE
		
	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
		return false
	}

	// Return sucessfull
	return true
}

func (wal443 wallet) addPassword(password string, comment string) {
	
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

	// Comment
	buff = bytes.NewBuffer([]byte(comment))
	if buff.Len() < COMMENT_BYTE_SIZE { 
		padding := COMMENT_BYTE_SIZE - buff.Len()
		for i := 0; i < padding ; i++ {
			_, err := buff.WriteString("\x00")
			check(err)
		} 
	}
	walEntry.comment = buff.Bytes()
	
	// Salt
	saltBytes := make([]byte, SALT_BYTE_SIZE)
    if _, err := rand.Read(saltBytes); err != nil {
        panic(err)
	}
	//s := fmt.Sprintf("%X", saltBytes)
	walEntry.salt = saltBytes
	
	// Add wallEntry to Passwords
	wal443.passwords = append(wal443.passwords, walEntry)
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
		if wal443 != nil && wal443.processWalletCommand(command, password, comment) {
			// wal443.saveWallet()
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

func truncateStringToBytes(data []byte, numBytes int) string {
	
	buff := bytes.NewBuffer([]byte(data))
	if buff.Len() > numBytes { buff.Truncate(numBytes) }// keep first numBytes and discard the rest
	return buff.String()
	
}

func getSHA1Hash(data string) []byte {
	hasher := sha1.New()
	hasher.Write([]byte(data))
	result := hasher.Sum(nil)

	fmt.Println(data)
	fmt.Printf("%x\n", result)

	return result
}