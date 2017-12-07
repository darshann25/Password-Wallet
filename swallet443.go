////////////////////////////////////////////////////////////////////////////////
//
//  File           : swallet443.go
//  Description    : This is the implementaiton file for the swallet password
//                   wallet program program.  See assignment details.
//
//  Collaborators  : Darshan Patel - ddp5131
//		     Rex Li - rjl5401
//		     Justin Dillman - jnd5215
//		     Raj Desai - rad5434
//		     Aditya Agarwal - aaa6026
//  Last Modified  : Dec 7, 2017 - 03:34am
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
	"github.com/marcusolsson/tui-go"
	
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
var usageText string = `USAGE: swallet443 [-h] [-v] <wallet-file> [create|add|del|show|chpw|reset|list]

where:
    -h - help mode (display this message)
    -v - enable verbose output

    <wallet-file> - wallet file to manage
	[create|add|del|show|chpw] - is a command to execute, where

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

	//temp - Needs UI
	//wal443.masterPassword = []byte("12345")
	masterPassword, valid := createSetMasterPasswordTextUI()
	
	if(valid) {
		wal443.masterPassword = []byte(masterPassword)
	} else {
		fmt.Println("Master password incorrectly set.\nPlease create the wallet again.")
		os.Exit(-1)
	}

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

	// temp - Need UI
	// wal443.masterPassword = []byte("12345")
	
	/*
	_, valid := createCheckMasterPasswordTextUI(string(wal443.masterPassword))
	
	if(valid == false) {
		fmt.Println("Incorrect Master Password. Unauthorized User.")
		os.Exit(-1)
	}
	*/
	masterPassword := createGetMasterPasswordTextUI()
	wal443.masterPassword = []byte(masterPassword)

	data, err := ioutil.ReadFile(wal443.filename + ".txt")
	check(err)

	lines := strings.Split(string(data), "\n")
	numLines := len(lines) - 1
	
	buffer := bytes.NewBuffer([]byte(lines[0] + "\n"))

	// check if masterPassword is correct by checking the HMAC
	for i := 1; i < numLines - 1; i++ {
		_, err := buffer.WriteString(lines[i] + "\n")
		check(err)
	}
	hashedPassword := getSHA1Hash(wal443.masterPassword)
	walletKey := truncateStringToBytes(hashedPassword, 16)

	hmac, err := base64.URLEncoding.DecodeString(lines[numLines - 1])
	check(err)
	valid := checkMAC(buffer.Bytes(), hmac, walletKey)
	
	if(valid) {
		genNumArr := strings.Split(lines[0], "||")
		genNum, err := strconv.Atoi(genNumArr[1])
		check(err)
		wal443.genNum = genNum


		for i := 1; i < numLines - 1; i++ {
			line := lines[i]
			_, err := buffer.WriteString(line)
			check(err)

			lineData := strings.Split(line, "||")
			aes_saltyPassword := lineData[1]
			comment := lineData[2]
			
			// initialize walletEntry
			var walEntry walletEntry

			// store comment
			walEntry.comment = []byte(comment)

			// decrypt saltyPassword
			saltyPassword, err := aes_decrypt(walletKey, aes_saltyPassword)
			check(err)

			saltyPasswordArr := strings.Split(saltyPassword, "||")
			walEntry.salt = []byte(saltyPasswordArr[0])
			walEntry.password = []byte(saltyPasswordArr[1])

			wal443.passwords = append(wal443.passwords, walEntry)

		}
	} else {

		fmt.Println("Incorrect Master Password. Unauthorized User.")
		os.Exit(-1)

	}

	//for index, value := range wal443.passwords {
	//	fmt.Printf("index : %d || password : %s\n", index, string(value.password))
	//}

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

func (wal443 wallet) saveWallet() (*wallet, bool) {

	wal443.genNum += 1

	data := time.Now().Format("2006-01-02 15:04:05") + "||" + strconv.Itoa(wal443.genNum) + "\n"
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

		// fmt.Println(len([]byte(aesPassword)))

		data := entryString + "||" + aesPassword + "||" + string(walEntry.comment) + "\n"
		// fmt.Println(data)

		_, err := buffer.WriteString(data)
		check(err)
		
	}

	hmac := createMAC(buffer.Bytes(), walletKey)
	hmacString := base64.URLEncoding.EncodeToString(hmac)
	buffer.WriteString(hmacString + "\n")
	err := ioutil.WriteFile(wal443.filename + ".txt", buffer.Bytes(), 0644)
	check(err)

	// Return successfully
	return &wal443, true
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : processWalletCommand
// Description  : This is the main processing function for the wallet
//
// Inputs       : walletFile - the name of the wallet file
//                command - the command to execute
// Outputs      : true if successful test, false if failure

func (wal443 wallet) processWalletCommand(command string) (*wallet, bool) {

	// Process the command 
	switch command {
	case "add":
		wal443 = wal443.addPassword()
		break

	case "del":
		wal443 = wal443.deletePassword()
		break
		
	case "show":
		wal443.showPassword()
		break
		
	case "chpw":
		wal443.changePassword()
		break

	case "reset":
		wal443, _ = wal443.resetPassword()
		break

	case "list":
		wal443.listPassword()
		break

	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
		return &wal443, false
	}

	// Return sucessfull
	return &wal443, true
}

func (wal443 wallet) addPassword() wallet{
	
	password, comment := createAddCommandTextUI()

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

func (wal443 wallet) deletePassword() (wallet) {
	
	entryNum := createDeleteCommandTextUI()
	// buff := bytes.NewBuffer([]byte(entryNum))
	
	/*
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
	}*/

	index := entryNum - 1
	if(index >=0 && index < len(wal443.passwords)) {
		wal443.passwords = append(wal443.passwords[:index], wal443.passwords[index + 1 :]...)
	} else {
		fmt.Println("Invalid Entry Number. Delete failed!")
		os.Exit(-1)
	}

	return wal443
}

func (wal443 wallet) showPassword() bool {
	
		maxEntryNum := len(wal443.passwords)
		entryText := createShowPasswordTextUI(maxEntryNum)
		entry, err := strconv.Atoi(entryText)
		check(err)
	
		if(entry > 0 && entry <= maxEntryNum) {
			createShowPasswordResultTextUI(entry, string(wal443.passwords[entry - 1].password))
		} else {
			fmt.Println("Incorrect entry number requested. Please use list command to find the entry number.")
			os.Exit(-1)
		}

		return true
	}

func (wal443 wallet) listPassword() bool{
	
		for i := 0; i < len(wal443.passwords); i++ {
	
			fmt.Printf("Entry : %d || Comment : %s \n", i + 1, wal443.passwords[i].comment)
		}
	
		return true
	}
func (wal443 wallet) changePassword() bool{
	
	maxEntryNum := len(wal443.passwords)
	
	entryText, newPassword := createChangePasswordTextUI(maxEntryNum)
	entry, err := strconv.Atoi(entryText)
	check(err)
	//perhaps the UI interface needs to be called here

	if(entry > 0 && entry <= maxEntryNum && newPassword != "") {
		wal443.passwords[entry - 1].password = []byte(newPassword)
	} else if (newPassword == ""){
		fmt.Println("Password is an invalid empty string. Please enter a valid password.")
	} else {
		fmt.Println("Incorrect entry number requested. Please use list command to find the entry number.")
		os.Exit(-1)
	}
	

	return true
	}	

func (wal443 wallet) resetPassword() (wallet, bool){
	
		masterPassword, valid := createSetMasterPasswordTextUI()
		
		if(valid) {
			// fmt.Printf("Old Password : %s\n", string(wal443.masterPassword))
			wal443.masterPassword = []byte(masterPassword)
			// fmt.Printf("New Password : %s\n", masterPassword)
		} else {
			fmt.Println("Master password incorrectly set.\nPlease reset the password again.")
			os.Exit(-1)
		}
	
		return wal443, valid
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

	//fmt.Printf("password [%s]\n", getopt.Arg(2))
	//password := strings.ToLower(getopt.Arg(2))

	//fmt.Printf("comment [%s]\n", getopt.Arg(3))
	//comment := getopt.Arg(3)

	// Now check if we are creating a wallet
	var ok bool
	if command == "create" {

		// Create and save the wallet as needed
		wal443 := createWallet(filename)
		
		if wal443 != nil {
			wal443, ok = wal443.saveWallet()
			if(ok == false) {
				fmt.Println("Error : Save Wallet Failed!")
				os.Exit(-1)
			}
		}

	} else {
		// Load the wallet, then process the command
		wal443 := loadWallet(filename)
		wal443, ok = wal443.processWalletCommand(command)
		if wal443 != nil && ok {
			wal443, ok = wal443.saveWallet()
			if(ok == false) {
				fmt.Println("Error : Save Wallet Failed!")
				os.Exit(-1)
			}
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
	// fmt.Printf("truncateStringToBytes : %d\n", buff.Len())
	
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
func checkMAC(message, messageMAC, key []byte) bool {
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

func createGetMasterPasswordTextUI() (masterPasswordInput string){

	var hiddenPassword string
	hide := true

	password1 := tui.NewEntry()
	password1.SetFocused(true)
	password1.OnChanged(func(e *tui.Entry) {
		input := e.Text()
		
		masterPasswordInput, hiddenPassword = updateHiddenPassword(hide, input, masterPasswordInput, hiddenPassword)
	
		if(hide) { 
			password1.SetText(hiddenPassword) 
		} else { 
			password1.SetText(masterPasswordInput) 
		} 
	})

	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Master Password : "))
	form.AppendRow(password1)

	status := tui.NewStatusBar("Ready.")
	usage := tui.NewStatusBar("USAGE : [Enter] - Check status of entered password. || [Hide/Unhide] - Hide/Unhide master password || PRESS [Esc] - Exit Command Window")

	enter := tui.NewButton("[Enter]")
	enter.OnActivated(func(b *tui.Button) {
		status.SetText("Thank you for entering the password.\n Press [Esc] to exit command window.")
	})

	hideButton := tui.NewButton("[Hide / Unhide]")
	hideButton.OnActivated(func(b *tui.Button) {
		hide = !hide
		
		if(hide) { 
			password1.SetText(hiddenPassword) 
		} else { 
			password1.SetText(masterPasswordInput) 
		}
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, enter),
		tui.NewPadder(1, 0, hideButton),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("File Locked : Please enter the Master Password\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
		usage,
	)

	tui.DefaultFocusChain.Set(password1, enter, hideButton)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}

	return
	}

func createSetMasterPasswordTextUI() (masterPasswordInput string, valid bool){
	
	var hiddenPassword1 string
	var hiddenPassword2 string
	var masterPasswordConfirm string
	hide := true

	valid = false
	password1 := tui.NewEntry()
	password1.SetFocused(true)
	password1.OnChanged(func(e *tui.Entry) {
		input := e.Text()
		
		masterPasswordInput, hiddenPassword1 = updateHiddenPassword(hide, input, masterPasswordInput, hiddenPassword1)

		if (hide) { 
			password1.SetText(hiddenPassword1) 
		} else { 
			password1.SetText(masterPasswordInput) 
		}
	})

	password2 := tui.NewEntry()
	password2.OnChanged(func(e *tui.Entry) {
		input := e.Text()
		
		masterPasswordConfirm, hiddenPassword2 = updateHiddenPassword(hide, input, masterPasswordConfirm, hiddenPassword2)
	
		if(hide) { 
			password2.SetText(hiddenPassword2) 
		} else { 
			password2.SetText(masterPasswordConfirm) 
		} 
	})

	hideButton := tui.NewButton("[Hide / Unhide]")
	hideButton.OnActivated(func(b *tui.Button) {
		hide = !hide
		
		if(hide) { 
			password1.SetText(hiddenPassword1)
			password2.SetText(hiddenPassword2) 
		} else { 
			password1.SetText(masterPasswordInput)
			password2.SetText(masterPasswordConfirm) 
		}
	})

	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Master Password : "), tui.NewLabel("Confirm Master Password : "))
	form.AppendRow(password1, password2)

	status := tui.NewStatusBar("Ready.")
	usage := tui.NewStatusBar("USAGE : [Enter] - Check status of entered passwords. || [Hide/Unhide] - Hide/Unhide passwords || PRESS [Esc] - Exit Command Window")

	enter := tui.NewButton("[Enter]")
	enter.OnActivated(func(b *tui.Button) {
		if (strings.Compare(password1.Text(), password2.Text()) == 0 && strings.Compare(password1.Text(), "") != 0) {
			status.SetText("Passwords match! Master password successfully set.\n Press Esc to exit command window.")
			valid = true
		} else {
			status.SetText("Passwords do not match. Please try again.")
			valid = false
		}
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, enter),
		tui.NewPadder(1, 0, hideButton),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("Set Master Password : Please enter and confirm the Master Password\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
		usage,
	)

	tui.DefaultFocusChain.Set(password1, password2, enter, hideButton)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}
	
	if(strings.Compare(password1.Text(), password2.Text()) == 0 && strings.Compare(password1.Text(), "") != 0) {
		valid = true
	} else {
		valid = false
	}

	return
}

func createAddCommandTextUI() (passwordInput, commentInput string){

	var hiddenPassword string
	hide := true

	password := tui.NewEntry()
	password.SetFocused(true)
	password.OnChanged(func(e *tui.Entry) {
		input := e.Text()
		
		passwordInput, hiddenPassword = updateHiddenPassword(hide, input, passwordInput, hiddenPassword)

		if(hide) { 
			password.SetText(hiddenPassword) 
		} else { 
			password.SetText(passwordInput) 
		}
	})

	comment := tui.NewEntry()
	comment.OnChanged(func(e *tui.Entry) {
		commentInput = e.Text()
	})

	hideButton := tui.NewButton("[Hide / Unhide]")
	hideButton.OnActivated(func(b *tui.Button) {
		hide = !hide
		
		if(hide) { 
			password.SetText(hiddenPassword)
		} else { 
			password.SetText(passwordInput)
		}
	})

	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Password"), tui.NewLabel("Comment"))
	form.AppendRow(password, comment)

	status := tui.NewStatusBar("Ready.")
	usage := tui.NewStatusBar("USAGE : [Enter] - Check status of entered password and comment. || [Hide/Unhide] - Hide/Unhide password || PRESS [Esc] - Exit Command Window")
	

	enter := tui.NewButton("[Enter]")
	enter.OnActivated(func(b *tui.Button) {
		status.SetText("Password Successfully Added.\n Press Esc to exit command window.")
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, enter),
		tui.NewPadder(1, 0, hideButton),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("Add Password Command : Please enter the Password and Comment!\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
		usage,
	)

	tui.DefaultFocusChain.Set(password, comment, enter, hideButton)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}

	return
}

func createDeleteCommandTextUI() (entryNum int) {
	
	entry := tui.NewEntry()
	entry.SetFocused(true)
	entry.OnChanged(func(e *tui.Entry) {
		num, err := strconv.Atoi(e.Text())
		check(err)
		entryNum = num
	})

	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Entry Number : "))
	form.AppendRow(entry)

	status := tui.NewStatusBar("Ready.")

	enter := tui.NewButton("[Enter]")
	enter.OnActivated(func(b *tui.Button) {
		status.SetText("Entry number successfully recorded.\n Press Esc to exit command window.")
	})
	help := tui.NewButton("[Help]")
	help.OnActivated(func(b *tui.Button) {
		status.SetText("If you do not know the entry number of the desired password, please use list and/or show command to find the entry number.\n")
	})


	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, enter),
		tui.NewPadder(1, 0, help),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("Delete Password Command : Please enter the Entry Number for the Password you want to Delete!\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
	)

	tui.DefaultFocusChain.Set(entry, enter, help)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}

	return
}

func createShowPasswordTextUI(maxEntryNum int) (entryText string){
	entry := tui.NewEntry()
	entry.SetFocused(true)
	entry.OnChanged(func(e *tui.Entry) {
		entryText = e.Text()
	})

	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Entry Number : "))
	form.AppendRow(entry)

	status := tui.NewStatusBar("Ready.")

	enter := tui.NewButton("[Enter]")
	enter.OnActivated(func(b *tui.Button) {
		num, err := strconv.Atoi(entryText)
		check(err)

		if(num > 0 && num <= maxEntryNum) {
			status.SetText("Valid entry number requested.\n Press Esc to exit command window.")
		} else {
			status.SetText("Invalid entry number requested. Please use list command to check entry numbers\n")
		}
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, enter),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("Show Password Command : Please enter the Entry Number for the password you want to see!\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
	)

	tui.DefaultFocusChain.Set(entry, enter)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}

	return
}

func createShowPasswordResultTextUI(entry int, passwordText string) {
	password := tui.NewLabel(passwordText)
	
	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Password for Entry Number " + string(entry) + " : "))
	form.AppendRow(password)

	status := tui.NewStatusBar("Ready.")

	help := tui.NewButton("[Help]")
	help.OnActivated(func(b *tui.Button) {
		status.SetText("If you do not know the entry number of the desired password, please use list command to find the entry number.\n")
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, help),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("Show Password Command : The requested password is displayed below!\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
	)

	tui.DefaultFocusChain.Set(help)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}

	return
}

func createChangePasswordTextUI(maxEntryNum int) (entryText string, newPassword string){
	
	var hiddenPassword string
	hide := true

	entry := tui.NewEntry()
	entry.SetFocused(true)
	entry.OnChanged(func(e *tui.Entry) {
		entryText = e.Text()
	})

	password := tui.NewEntry()
	// password.SetFocused(true)
	password.OnChanged(func(e *tui.Entry) {
		input := e.Text()
		
		newPassword, hiddenPassword = updateHiddenPassword(hide, input, newPassword, hiddenPassword)	

		if(hide) { 
			password.SetText(hiddenPassword) 
		} else { 
			password.SetText(newPassword) 
		}
		
	})

	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Entry Number : "), tui.NewLabel("New Password : "))
	form.AppendRow(entry, password)

	status := tui.NewStatusBar("Ready.")
	usage := tui.NewStatusBar("USAGE : [Enter] - Check status of entered password and entry number. || [Hide/Unhide] - Hide/Unhide password || PRESS [Esc] - Exit Command Window")
	
	enter := tui.NewButton("[Enter]")
	enter.OnActivated(func(b *tui.Button) {
		num, err := strconv.Atoi(entryText)
		check(err)

		if(num > 0 && num <= maxEntryNum) {
			status.SetText("Valid entry number requested.\n Press Esc to exit command window.")
			newPassword = password.Text()
		} else {
			status.SetText("Invalid entry number requested. Please use list command to check entry numbers\n")
		}
	})

	hideButton := tui.NewButton("[Hide / Unhide]")
	hideButton.OnActivated(func(b *tui.Button) {
		hide = !hide
		
		if(hide) { 
			password.SetText(hiddenPassword)
		} else { 
			password.SetText(newPassword)
		}
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, enter),
		tui.NewPadder(1, 0, hideButton),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("Show Password Command : Please enter the Entry Number for the password you want to see!\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
		usage,
	)

	tui.DefaultFocusChain.Set(entry, password, enter, hideButton)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}

	return
}

func updateHiddenPassword(hide bool, input, password, hiddenPassword string) (string, string){
	if (hide) {
		if (len(hiddenPassword) > len(input)) {
			password = password[:len(input)]
			hiddenPassword = hiddenPassword[:len(input)]
		} else {
			for _, char := range input {
				if (char != '*') {
					password += string(char)
					hiddenPassword += string("*")
				}
			}
		}
	} else {
		if (len(password) > len(input)) {
			password = input
			hiddenPassword = hiddenPassword[:len(input)]
		} else {
			password = input
			hiddenPassword += string("*")
		}
	}

	return password, hiddenPassword
}

func createCheckMasterPasswordTextUI(expectedMasterPassword string) (masterPasswordInput string, valid bool){
	
	var hiddenPassword string
	hide := true
	valid = false
	password1 := tui.NewEntry()
	password1.SetFocused(true)
	password1.OnChanged(func(e *tui.Entry) {
		input := e.Text()
		for _, char := range input {
			if (char != '*') {
				masterPasswordInput += string(char)
				hiddenPassword += string("*")
				if len(hiddenPassword) > len(input) {
					masterPasswordInput = masterPasswordInput[:len(input)]
					hiddenPassword = hiddenPassword[:len(input)]
				}

				if(hide) { 
					password1.SetText(hiddenPassword) 
				} else { 
					password1.SetText(masterPasswordInput) 
				} 
			}
		}
	})

	form := tui.NewGrid(0, 0)
	form.AppendRow(tui.NewLabel("Master Password : "))
	form.AppendRow(password1)

	status := tui.NewStatusBar("Ready.")
	usage := tui.NewStatusBar("USAGE : [Enter] - Check status of entered password. || [Hide/Unhide] - Hide/Unhide master password || PRESS [Esc] - Exit Command Window")

	enter := tui.NewButton("[Enter]")
	enter.OnActivated(func(b *tui.Button) {
		if (strings.Compare(password1.Text(), expectedMasterPassword) == 0) {
			status.SetText("Correct Password!\n Press Esc to exit command window.")
			valid = true
		} else {
			status.SetText("Incorrect Password. Please try again.")
			valid = false
		}
	})

	hideButton := tui.NewButton("[Hide / Unhide]")
	hideButton.OnActivated(func(b *tui.Button) {
		hide = !hide
		
		if(hide) { 
			password1.SetText(hiddenPassword) 
		} else { 
			password1.SetText(masterPasswordInput) 
		}
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, enter),
		tui.NewPadder(1, 0, hideButton),
	)

	window := tui.NewVBox(
		tui.NewPadder(0, 0, tui.NewLabel("Authenticate User : Please enter the Master Password\n")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	wrapper := tui.NewVBox(
		tui.NewSpacer(),
		window,
		tui.NewSpacer(),
	)
	content := tui.NewHBox(tui.NewSpacer(), wrapper, tui.NewSpacer())

	root := tui.NewVBox(
		content,
		status,
		usage,
	)

	tui.DefaultFocusChain.Set(password1, enter, hideButton)

	ui := tui.New(root)
	ui.SetKeybinding("Esc", func() { ui.Quit() })

	if err := ui.Run(); err != nil {
		panic(err)
	}
	
	if(strings.Compare(password1.Text(), expectedMasterPassword) == 0) {
		valid = true
	} else {
		valid = false
	}

	return
}