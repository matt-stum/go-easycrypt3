package main

import (
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/eiannone/keyboard"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const cookie string = "EasyCrypt3::"
const blocksize int = aes.BlockSize // 16
const buflen int = 4 * 1024         // must be a multiple of blocksize (4k is the most common physical disk block size, so this works well)

var theList []string
var errList []string

var ErrShortWrite = errors.New("short write occurred")
var ErrPrematureEOF = errors.New("premature EOF encountered")
var ErrInvalidCookie = errors.New("invalid cookie")
var ErrReadingPasswordValidation = errors.New("error retrieving password validation")
var ErrPasswordValidationFailed = errors.New("password validation failed")
var ErrReadingFilename = errors.New("error retrieving filename")
var ErrReadingIV = errors.New("error retrieving IV")

const FILEMODE_READONLY = os.O_RDONLY                           // source
const FILEMODE_CREATEONLY = os.O_RDWR | os.O_CREATE | os.O_EXCL // target + nooverwrite
const FILEMODE_CREATE = os.O_RDWR | os.O_CREATE | os.O_TRUNC    // target + overwrite
const FILEMODE_WRITE = os.O_RDWR                                // secure delete
const FILEPERM_CREATE = 0666                                    // rw-rw-rw- ?? maybe?
const FILEPERM_READ = 0                                         // used when not creating a new file

var rootCmd *cobra.Command
var doingIt bool = false
var password *string
var isWhatIf *bool
var isQuiet *bool
var isVerbose *bool
var isConfirm *bool
var userConfirmed rune = 'N' // Y | N | A | Q
var isRecursive *bool
var isOverwrite *bool
var eMode *string
var dMode *string
var destFolder *string
var destFile *string

var exitFunc func()

type ecHeader struct {
	// Absolute path of source
	Name               string
	Stream             *os.File
	Cookie             string
	PasswordValidation []byte
	// Stored path of original plaintext (assumed to be absolute)
	Filename string
	IV       []byte
}

func _sha256(message []byte) []byte {
	s256 := sha256.New()
	s256.Write(message)
	return s256.Sum(nil)
}

func _sha512(message []byte) []byte {
	s512 := sha512.New()
	s512.Write(message)
	return s512.Sum(nil)
}

func _hmac512(message, key []byte) []byte {
	h512 := hmac.New(sha512.New, key)
	h512.Write(message)
	return h512.Sum(nil)
}

func _pbkdf2_sha256(password string, salt []byte) []byte {
	hash, err := pbkdf2.Key(sha256.New, password, salt, 104201, 32)
	if err != nil {
		panic(err)
	}
	return hash
}

func _pbkdf2_sha512(password string, salt []byte) []byte {
	hash, err := pbkdf2.Key(sha512.New, password, salt, 104201, 64)
	if err != nil {
		panic(err)
	}
	return hash
}

func _PKCS7Padding(plaintext []byte, blockSize int) []byte {
	paddingSize := blockSize - (len(plaintext) % blockSize)
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte(paddingSize)
	}
	return append(plaintext, padding...)
}

func _PKCS7UnPadding(src []byte) ([]byte, error) {
	buflen := len(src)
	padlen := int(src[buflen-1])
	if padlen > buflen {
		return nil, errors.New("invalid padding length")
	}
	for _, x := range src[buflen-padlen:] {
		if int(x) != padlen {
			return nil, errors.New("invalid pkcs7 padding value")
		}
	}
	return src[:(buflen - padlen)], nil
}

// This prepares a Windows absolute path to be parseable on linux as well.
// It detects something that looks like a UNC (starts with double-backslash) or
// drive letter and replaces all following backslashes with slashes.
func toSlash(path string) string {
	if matched, _ := regexp.MatchString(`^(?:\\\\|[a-zA-Z]\:).*$`, path); matched {
		path = path[0:2] + strings.ReplaceAll(path[2:], `\`, `/`)
	}
	return path
}

// Simplified version of io.ReadFull, where error!=nil if n<len(buffer)
// except error==EOF indicates a successful partial final read.  Use this
// when you want to know if the partial read is b/c of EOF rather than
// having to make another read to verify.
func greedyRead(reader io.Reader, buffer []byte) (n int, err error) {
	buflen := len(buffer)
	for n < buflen && err == nil {
		var nr int
		nr, err = reader.Read(buffer[n:])
		n += nr
	}
	return
}

func readCookie(ifile io.Reader) (string, error) {
	buff := make([]byte, len(cookie))
	_, e := greedyRead(ifile, buff)
	if e != nil && e != io.EOF {
		return string(buff), e
	}
	if !slices.Equal(buff, []byte(cookie)) {
		return string(buff), ErrInvalidCookie
	}
	return string(buff), nil
}

func readPasswordValidation(ifile io.Reader) ([]byte, error) {
	buff := make([]byte, 64)
	_, e := greedyRead(ifile, buff)
	if e != nil && e != io.EOF {
		return nil, e
	}
	return buff, nil
}

// The filename is stored as a null-terminated string, so read byte-by-byte until we hit 0.
func readFilename(ifile io.Reader) (string, error) {
	sb := make([]byte, 0) // StringBuilder
	buff := make([]byte, 1)
	for {
		n, e := io.ReadFull(ifile, buff)
		if e != nil {
			return "", e
		}
		if n == 0 || buff[0] == 0 { // null or EOF, so we're done either way
			break
		}
		sb = append(sb, buff...)
	}
	return string(sb), nil
}

func readIV(ifile io.Reader) ([]byte, error) {
	buff := make([]byte, blocksize)
	_, e := io.ReadFull(ifile, buff)
	if e != nil {
		return nil, e
	}
	return buff, nil
}

func isEncrypted(src string) (ecHeader, error) {
	allIsWell := false

	header := ecHeader{Name: src}
	ifile, err := os.OpenFile(src, FILEMODE_READONLY, FILEPERM_READ)
	if err != nil {
		return header, err
	}
	defer func() {
		if !allIsWell {
			ifile.Close()
		}
	}() // we want this to stay open if all goes well
	header.Stream = ifile

	c, err := readCookie(ifile)
	if err != nil {
		return header, err
	}
	header.Cookie = c

	pval, err := readPasswordValidation(ifile)
	if err != nil {
		return header, ErrReadingPasswordValidation
	}
	header.PasswordValidation = pval

	fname, err := readFilename(ifile)
	if err != nil {
		return header, ErrReadingFilename
	}
	header.Filename = fname

	iv, err := readIV(ifile)
	if err != nil {
		return header, ErrReadingIV
	}
	header.IV = iv

	allIsWell = true
	return header, nil
}

func DecryptStream(ifile io.Reader, pwdhash, iv []byte, ofile io.Writer) error {

	pbuff := make([]byte, buflen) // plaintext buffer
	np := 0                       // number of plaintext bytes in pbuff
	cbuff := make([]byte, buflen) // ciphertext buffer
	eof := false                  // persistent indicator that we've hit EOF
	var nr int                    // number of bytes read
	var er, ew, eu error          // read error, write error, unpadding error

	alg, _ := aes.NewCipher(pwdhash)
	decryptor := cipher.NewCBCDecrypter(alg, iv)

	for {
		if !eof { // read into ciphertext buffer
			nr, er = greedyRead(ifile, cbuff[:buflen])
			if er != nil && er != io.EOF {
				return er
			}
		}

		if nr == 0 && er == io.EOF { // previous plaintext buffer was last, so unpad and mark eof
			pbuff, eu = _PKCS7UnPadding(pbuff[:np])
			if eu != nil {
				return eu
			}
			np = len(pbuff)
			eof = true
		}

		if np > 0 { // write plaintext buffer to output
			_, ew = ofile.Write(pbuff[:np])
			if ew != nil {
				return ew
			}
		}

		if eof {
			break
		}

		decryptor.CryptBlocks(pbuff[:buflen], cbuff[:nr]) // decrypt ciphertext buffer into plaintext buffer (overwriting it)
		np = nr                                           // set number of plaintext bytes in case it wasn't a full ciphertext buffer

		if er == io.EOF { // hack avoid extra 0-byte read from ifile (which is okay... but not all readers might be)
			nr = 0 // hack to trigger unpadding
			eof = true
		}

	} // loop

	return nil
}

func EncryptFile(source, destination string) error {

	var iv []byte = make([]byte, 16)
	rand.Read(iv)

	// ...

	ifile, err := os.OpenFile(source, FILEMODE_READONLY, FILEPERM_READ)
	if err != nil {
		return err
	}
	defer ifile.Close()

	_, err = os.Stat(destination)
	if err == nil && !*isOverwrite {
		return errors.New("skipping: destination exists and --overwrite not specified")
	}

	flags := ifElse(*isOverwrite, FILEMODE_CREATE, FILEMODE_CREATEONLY)
	ofile, err := os.OpenFile(destination, flags, FILEPERM_CREATE)
	if err != nil {
		return err
	}
	defer ofile.Close()

	// NOTE: buflen MUST be a multiple of cipher algorithm block size (aes: 16)
	// Since 4k is also a common disk block size it's a decent choice
	const buflen int = 4 * 1024
	const blocksize int = aes.BlockSize

	pwdhash := _pbkdf2_sha256(*password, iv)
	alg, _ := aes.NewCipher(pwdhash)
	encryptor := cipher.NewCBCEncrypter(alg, iv)

	// WRITE HEADER
	_, err = ofile.Write([]byte(cookie))
	if err != nil {
		return err
	}
	_, err = ofile.Write(_pbkdf2_sha512(*password, iv))
	if err != nil {
		return err
	}
	_, err = ofile.Write(append([]byte(source), byte(0)))
	if err != nil {
		return err
	}
	_, err = ofile.Write(iv)
	if err != nil {
		return err
	}

	buffer := make([]byte, buflen)
	eof := false
	for {

		// using GreedyRead means we can confidently identify last block (for padding) with n<buflen as long as err==EOF
		n, err := greedyRead(ifile, buffer[:buflen])
		if err != nil && err != io.EOF {
			return err
		}

		if n < buflen { // EOF
			buffer = _PKCS7Padding(buffer[:n], blocksize) // TODO: CHANGE TO alg.BlockSize()
			n = len(buffer)
			eof = true
		}

		// TODO: ENCRYPT BUFFER
		encryptor.CryptBlocks(buffer[:n], buffer[:n])

		_, err = ofile.Write(buffer[:n])
		if err != nil {
			return err
		}
		if eof {
			break
		}
	} // loop

	return nil
}

func validatePasswordV1(pwd string, pval, iv []byte) bool {
	return hmac.Equal(pval, _hmac512(_sha512([]byte(pwd)), iv)) // use hmac.Equal() to compare to avoid timing side-channels, blah blah blah
}
func validatePasswordV2(pwd string, pval, iv []byte) bool {

	return hmac.Equal(pval, _pbkdf2_sha512(pwd, iv)) // use hmac.Equal() to compare to avoid timing side-channels, blah blah blah
}

func expandFileList(args []string, recursive bool) ([]string, []string) {
	result := make([]string, 0)
	eresult := make([]string, 0)
	que := list.New()
	for _, entry := range args {
		que.PushFront(entry)
	}
	for que.Len() > 0 {
		entry := que.Remove(que.Back()).(string)
		abs, e := filepath.Abs(entry)
		if e != nil {
			eresult = append(eresult, fmt.Sprint("cannot expand path:", entry))
			continue
		}
		fi, e := os.Stat(abs)
		if e != nil {
			// let's see if it's a wildcard - NOTE: MUST DOCUMENT THAT THIS IS CASE-SENSITIVE.  ex. "easy*" won't match ./EasyCrypt but "Easy*" will.
			isWildcard := false
			matches, e := filepath.Glob(abs)
			if e != nil {
				eresult = append(eresult, fmt.Sprint("invalid search pattern: ", abs))
				continue
			}
			for _, entry := range matches {
				if !slices.ContainsFunc(result, func(x string) bool { return strings.EqualFold(x, entry) }) {
					que.PushFront(entry)
				}
				isWildcard = true
			}
			if !isWildcard {
				eresult = append(eresult, fmt.Sprint("no such file or folder: ", abs))
			}
			continue
		} // stat fail
		if !fi.IsDir() && !slices.ContainsFunc(result, func(x string) bool { return strings.EqualFold(x, abs) }) {
			result = append(result, abs)
			continue

		} // file exists
		if fi.IsDir() {
			de, e := os.ReadDir(abs)
			if e != nil {
				eresult = append(eresult, fmt.Sprint("could not read directory: ", abs))
				continue
			}
			for _, entry := range de {
				abs := filepath.Join(abs, entry.Name())
				if entry.IsDir() {
					if recursive {
						que.PushFront(abs)
					}
					continue
				}

				if !slices.ContainsFunc(result, func(x string) bool { return strings.EqualFold(x, abs) }) {
					result = append(result, abs)
				}

			}
		} // folder exists
	} // que loop
	return result, eresult
}

func printErr(f string, x ...any) {
	color.Set(color.FgRed)
	fmt.Printf(f+"\n", x...)
	color.Unset()
}

func validateDeleteMode() bool {
	validDeleteModes := []string{"none", "auto", "secure", "fast"}
	*dMode = strings.ToLower(*dMode)
	if !slices.Contains(validDeleteModes, *dMode) {
		printErr(`Error: invalid argument for "--delete" flag: must be one of none, auto, secure, fast`)
		rootCmd.Usage()
		return false
	}
	return true
}

func validateCryptMode() bool {
	validModes := []string{"toggle", "encrypt", "decrypt"}
	*eMode = strings.ToLower(*eMode)
	if !slices.Contains(validModes, *eMode) {
		printErr(`Error: invalid argument for "--mode" flag: must be one of toggle, encrypt, decrypt`)
		rootCmd.Usage()
		return false
	}
	return true
}

func validateDestinationFile() bool {
	if *destFile != "" && len(theList) > 1 {
		printErr(`Error: invalid usage of "--dest-file" flag: cannot be used when more than one file is being processed`)
		rootCmd.Usage()
		return false
	}

	if *destFile != "" {
		dest, err := filepath.Abs(*destFile)
		if err != nil {
			printErr(`Error: Could not expand file path "%v"`, *destFile)
			return false
		}
		fi, err := os.Stat(dest)
		if err == nil { // exists
			if fi.IsDir() {
				printErr(`Error: Destination file is actually a directory "%v"`, dest)
				return false
			}
			if !*isOverwrite {
				printErr(`Error: Destination file already exists. Use "--overwrite" if you wish to overwrite existing files. "%v"`, dest)
				return false
			}
			*destFile = dest
		}

	}
	return true
}

func validateDestinationFolder() bool {
	if *destFolder != "" { // && allow-create
		dest, err := filepath.Abs(*destFolder)
		if err != nil {
			printErr(`Error: Could not expand folder path "%v"`, *destFolder)
			return false
		}
		fi, err := os.Stat(dest)
		if err != nil {
			printErr(`Error: Destination folder does not exist "%v"`, dest)
			return false
		}
		if !fi.IsDir() {
			printErr(`Error: Destination folder is not a directory "%v"`, dest)
			return false
		}
		*destFolder = dest
	}
	return true
}

func tryDecrypt(header ecHeader) error {
	defer header.Stream.Close()
	if !(*eMode == "toggle" || *eMode == "decrypt") {
		printAction(fmt.Sprintf("\nSkipping %s", header.Name))
		return errors.New("skipping due to mode")
	}
	destination := ifElse(
		*destFile != "",
		*destFile,
		filepath.Join(ifElse(*destFolder != "", *destFolder, filepath.Dir(header.Name)), filepath.Base(toSlash(header.Filename))))
	printAction(fmt.Sprintf("\nDecrypting %s\n        to %s", header.Name, destination))
	_, err := os.Stat(destination)
	if err == nil && !*isOverwrite {
		return errors.New("skipping: destination exists and --overwrite not specified")
	}
	isV1 := validatePasswordV1(*password, header.PasswordValidation, header.IV)
	isV2 := !isV1 && validatePasswordV2(*password, header.PasswordValidation, header.IV)
	if !(isV1 || isV2) {
		return errors.New("skipping: password not valid")
	}

	if !*isWhatIf {
		err := askForConfirmation()
		if err != nil {
			return err
		}
		flags := ifElse(*isOverwrite, FILEMODE_CREATE, FILEMODE_CREATEONLY)
		ofile, err := os.OpenFile(destination, flags, FILEPERM_CREATE)
		if err != nil {
			return err
		}
		defer ofile.Close()
		pwdHash := ifElse(isV1, _sha256(_sha256([]byte(*password))), _pbkdf2_sha256(*password, header.IV))
		err = DecryptStream(header.Stream, pwdHash, header.IV, ofile)
		return err
	}

	return nil
}

func tryEncrypt(fname string) error {
	if !(*eMode == "toggle" || *eMode == "encrypt") {
		printAction(fmt.Sprintf("\nSkipping %s", fname))
		return errors.New("skipping due to mode")
	}
	destination := ifElse(
		*destFile != "",
		*destFile,
		filepath.Join(ifElse(*destFolder != "", *destFolder, filepath.Dir(fname)), filepath.Base(fname)+".crypt"))
	printAction(fmt.Sprintf("\nEncrypting %s\n        to %s", fname, destination))
	_, err := os.Stat(destination)
	if err == nil && !*isOverwrite {
		return errors.New("skipping: destination exists and --overwrite not specified")
	}

	if !*isWhatIf {
		err := askForConfirmation()
		if err != nil {
			return err
		}
		err = EncryptFile(fname, destination)
		return err
	}
	return nil
}

func tryDelete(filename, mode string) error {
	if mode == "none" {
		return nil
	}
	fi, err := os.Stat(filename)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return errors.New("cannot delete a folder")
	}
	if mode == "secure" {
		printAction(fmt.Sprintf("Overwriting %s", filename))
		printVerbose(fmt.Sprintf("(%v bytes)", fi.Size()))
		if !*isWhatIf {
			ofile, err := os.OpenFile(filename, FILEMODE_WRITE, FILEPERM_READ)
			if err != nil {
				return err
			}
			defer ofile.Close()
			remaining := fi.Size()
			const buflen int64 = 4 * 1024
			buffer := make([]byte, buflen)
			for remaining > 0 {
				n, err := ofile.Write(buffer[:ifElse(remaining >= buflen, buflen, remaining)])
				if err != nil {
					return err
				}
				remaining = remaining - int64(n)
			}
			ofile.Close()
		} // whatif
	}
	printAction(fmt.Sprintf("Deleting %s", filename))
	if !*isWhatIf {
		err = os.Remove(filename)
		if err != nil {
			return err
		}
	}
	return nil
}

func doit(cmd *cobra.Command, args []string) {
	doingIt = true // this will not trigger if there was a cli error or --help was asked for
}

// How many programs have a function like this b/c Go refuses to introduce a ternary operator?
func ifElse[T any](expr bool, ifTrue T, ifFalse T) T {
	if expr {
		return ifTrue
	}
	return ifFalse

}

func printNormal(line string) {
	if !*isQuiet {
		fmt.Println(line)
	}
}
func printVerbose(line string) {
	if *isVerbose {
		fmt.Println(line)
	}
}
func printAction(line string) {
	if !*isQuiet || *isConfirm {
		fmt.Println(line)
	}
}

func askForConfirmation() error {
	if *isConfirm && userConfirmed != 'A' {
		fmt.Print("\nPerform? [Y]es, [N]o, [A]ll, [Q]uit  ")
		for {
			ch, _, _ := keyboard.GetSingleKey()
			ch = unicode.ToUpper(ch)
			if ch == 'Y' || ch == 'N' || ch == 'A' || ch == 'Q' {
				userConfirmed = ch
				fmt.Println(string(userConfirmed))
				break
			}
		}
		if userConfirmed == 'N' || userConfirmed == 'Q' {
			return errors.New("skipping: no confirmation")
		}
	}
	return nil
}

func main() {
	exitFunc = getExitFunc()
	if exitFunc != nil {
		defer exitFunc()
	}

	rootCmd = &cobra.Command{Use: "EasyCrypt3.exe [flags] {file|folder ...}", Run: doit}
	w, _, _ := term.GetSize(int(os.Stdout.Fd()))
	rootCmd.SetUsageTemplate(strings.Replace(rootCmd.UsageTemplate(), ".FlagUsages ", fmt.Sprintf(".FlagUsagesWrapped %d ", ifElse(w > 0, w, 80)), -1))

	rootCmd.Args = cobra.MinimumNArgs(1)

	rootCmd.Version = "3.1"
	rootCmd.Long = `
EasyCrypt is a command-line file encryption tool.

One or more files can be drag-n-dropped onto the EasyCrypt3.exe icon
in Windows Explorer.

It can be run from the command-line where you can specify one or more
files or folders separated by spaces. Additional flags can be used to
alter the behavior. For example, use --whatif to see what *would* happen
without actually making any changes to the file(s).
`
	password = rootCmd.PersistentFlags().String("password", "", "Password used to encrypt or decrypt. You will be prompted if missing.")
	isWhatIf = rootCmd.PersistentFlags().Bool("whatif", false, "Go through the motions w/o making changes")
	isQuiet = rootCmd.PersistentFlags().Bool("quiet", false, "Suppress most output")
	isVerbose = rootCmd.PersistentFlags().Bool("verbose", false, "Include additional output")
	isConfirm = rootCmd.PersistentFlags().Bool("confirm", true, "Confirm actions before performed")
	eMode = rootCmd.PersistentFlags().String("mode", "toggle", "{toggle|encrypt|decrypt} If a value other than toggle is specified, files will be skipped if the mode matches the file's existing condition.") // if file is already encrypted, --mode=encrypt will do nothing
	isOverwrite = rootCmd.PersistentFlags().Bool("overwrite", false, "Overwrite destination file if exists.")
	isRecursive = rootCmd.PersistentFlags().Bool("recursive", false, "Recursive directory traversal")
	dMode = rootCmd.PersistentFlags().String("delete", "auto", "Deletion mode (none,auto,secure,fast)")
	destFolder = rootCmd.PersistentFlags().String("dest-folder", "", "Folder to receive processed file(s)")
	destFile = rootCmd.PersistentFlags().String("dest-file", "", "Override destination file name")
	rootCmd.MarkFlagsMutuallyExclusive("quiet", "verbose")
	//rootCmd.MarkFlagsMutuallyExclusive("whatif", "confirm")
	rootCmd.MarkFlagsMutuallyExclusive("dest-folder", "dest-file")

	if len(os.Args) <= 1 {
		rootCmd.Help() // simulates -h/--help so that you get the Long description (except it doesn't show -h/--help as options in flags section. wtf?)
		return
	}

	rootCmd.Execute()
	if !doingIt {
		return
	}
	if !validateDeleteMode() {
		return
	}
	if !validateCryptMode() {
		return
	}

	theList, errList = expandFileList(rootCmd.Flags().Args(), *isRecursive)

	if !validateDestinationFile() {
		return
	}

	if !validateDestinationFolder() {
		return
	}

	mapYesNo := map[bool]string{false: color.RedString("No"), true: color.GreenString("Yes")}
	// GREEN VS RED feels too much like GOOD VS BAD when viewed... but Overwrite: Yes is definitely DANGER DANGER.

	printVerbose(fmt.Sprintf("What-If:      %s", mapYesNo[*isWhatIf]))
	printVerbose(fmt.Sprintf("Mode:         '%s'", *eMode))
	printVerbose(fmt.Sprintf("Delete:       '%s'", *dMode))
	printVerbose(fmt.Sprintf("Overwrite:    %s", mapYesNo[*isOverwrite]))
	printVerbose(fmt.Sprintf("Destination:  %s", ifElse(*destFile != "", *destFile, ifElse(*destFolder != "", *destFolder, "<default>"))))
	printVerbose("")

	if !*isQuiet { // no need to iterate the loop if we know it will be suppressed
		for _, fname := range theList {
			printNormal(fname)
		}
		for _, msg := range errList {
			printErr("%s\n", msg)
		}
		printNormal("")
	}

	if len(theList) == 0 {
		return
	}

	// wait til we know there are files to process to prompt for password if missing
	if *password == "" {
		fmt.Println("\n(Press Ctrl-C to abort.)")
		fmt.Print(color.GreenString("Password: "))
		pwdbytes, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println(strings.Repeat("*", len(string(pwdbytes))))
		if e != nil && e != io.EOF { // ctrl-z will exit with EOF only if no characters typed. otherwise it's no different than hitting enter.
			panic(e)
		}

		fmt.Print(color.GreenString("Verify: "))
		pwdbytes2, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println(strings.Repeat("*", len(string(pwdbytes2))))
		if e != nil && e != io.EOF { // ctrl-z will exit with EOF only if no characters typed. otherwise it's no different than hitting enter.
			panic(e)
		}
		if !slices.Equal(pwdbytes, pwdbytes2) {
			printErr("Passwords did not match")
			return
		}
		*password = string(pwdbytes)
	} //  password prompt

	for _, fname := range theList {
		if userConfirmed == 'Q' {
			printErr("aborting: confirmation quit")
			break
		}
		header, err := isEncrypted(fname)
		if err == nil { // encrypted
			err := tryDecrypt(header) // file is closed when this returns, no matter what
			if err != nil {
				printErr("%v", err)
				continue // skip any attempt at deletion
			}

			err = tryDelete(fname, ifElse(*dMode == "auto", "fast", *dMode))
			if err != nil {
				printErr("%v", err)
				continue
			}

		} else { // plaintext

			err := tryEncrypt(fname)
			if err != nil {
				printErr("%v", err)
				continue // skip any attempt at deletion
			}

			err = tryDelete(fname, ifElse(*dMode == "auto", "secure", *dMode))
			if err != nil {
				printErr("%v", err)
				continue
			}

		}
	}

}
