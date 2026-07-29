// Command hashpw prints a bcrypt hash for ADMIN_PASSWORD_HASH, so you don't
// need a running Docker daemon (for `caddy hash-password`) just to bootstrap
// this service.
//
//	go run ./cmd/hashpw                  # prompts, nothing lands in shell history
//	go run ./cmd/hashpw -cost 12 -stdin  # reads the password from stdin
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	cost := flag.Int("cost", 12, "bcrypt cost")
	fromStdin := flag.Bool("stdin", false, "read the password from stdin instead of prompting")
	flag.Parse()

	var pw string
	if *fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(os.Stderr, "read stdin:", err)
			os.Exit(1)
		}
		pw = strings.TrimRight(line, "\r\n")
	} else {
		fmt.Fprint(os.Stderr, "password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read password:", err)
			os.Exit(1)
		}
		pw = string(b)
	}

	if pw == "" {
		fmt.Fprintln(os.Stderr, "empty password")
		os.Exit(1)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), *cost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	fmt.Println(string(h))
}
