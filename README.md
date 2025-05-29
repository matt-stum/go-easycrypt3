# EasyCrypt

EasyCrypt is a command-line file encryption tool.

The contents are encrypted with AES256 using an encryption key derived from a user-supplied password using PBKDF2-SHA256-104201

When encrypting, the plaintext file is overwritten before deletion. When decrypting, the ciphertext file is simply deleted.

```Text
Usage:
EasyCrypt3.exe [flags] {file|folder ...}

Flags:
      --confirm              Confirm actions before performed
                             (default true)
      --delete string        Deletion mode (none,auto,secure,fast)
                             (default "auto")
      --dest-file string     Override destination file name
      --dest-folder string   Folder to receive processed file(s)
      --mode string          {toggle|encrypt|decrypt} If a value
                             other than toggle is specified, files
                             will be skipped if the mode matches the
                             file's existing condition. (default
                             "toggle")
      --overwrite            Overwrite destination file if exists.
      --password string      Password used to encrypt or decrypt.
                             You will be prompted if missing.
      --quiet                Suppress most output
      --recursive            Recursive directory traversal
      --verbose              Include additional output
      --whatif               Go through the motions w/o making changes
```
