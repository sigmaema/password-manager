# Password manager

! Absolutely not a secure way to store passwords !

- uses Fernet to encrypt and decrypt passwords
- saves everything in a text file, keyword and user is stored as a classic string, password is stored as encrypted text
- for ex.: keyword|user|gAAAAABoH63pSuMKBhy9ohrtyxIKLNvaidZT79707vn-m8sf_evIVC3kfTGIOtjT4E1VRdUgEut4M8b9CLRrPCnrz4td2Mx9eg==
- on first use, random salt is generated and stored as a salt.salt file (user should not have another file with the same name). This salt, combined with the user-entered master password, is used to derive the encryption key
- this way, the master password itself is never stored