# UYA Medius Encryption

Encrypts and decrypts Up Your Arsenal (PS2) medius messages.

## TODO

The first 4 messages sent between the client and the server establish the keys used to encrypt all future data. They themselves are encrypted using a different algorithm than the proprietary RC4-SHA1 algorithm used for the rest of the messages. Support for decrypting those are unsupported at the moment, though it is possible to relay these messages to the client and have it decrypt the cipher.
