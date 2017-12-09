# Password Wallet
Password Wallet is highly-secure password holder commandline application. It uses AES encryption to store the password and query them.

```
USAGE: swallet443 [-h] [-v] <wallet-file> [create|add|del|show|chpw|reset|list]

where:
    -h - help mode (display this message)
    -v - enable verbose output (prints debugging flags)

    <wallet-file> - wallet file to manage (without ".txt" appended)
	[create|add|del|show|chpw] - is a command to execute, where

     	create - create a new wallet file
     	add - adds a password to the wallet
     	del - deletes a password from the wallet
     	show - show a password in the wallet
     	chpw - changes the password for an entry in the wallet
     	reset - changes the password for the wallet
     	list - list the entries in the wallet (without passwords)
```