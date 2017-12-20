# client-server_encrypt-decrypt

File encryption and description in c, encrypting or decrypting server will encrypt/decrypt the file submitted by the client

Enter "compilall" to compile the 2 server and client programs and the key generator

Key generator usage:
  keygen <keylength> [ > mykeyfile ]
  -keylength is the length of the key file in characters. keygen outputs to stdout
  
Server usage:
 otp_enc_d <listening_port> [&]
 otp_dec_d <listening_port> [&]

Client usage:
 otp_enc <plaintext> <key> <port>
 - plaintext is the name of a file in the current directory that contains the plaintext you wish to encrypt.
 - key contains the encryption key you wish to use to encrypt the text.
 - port is the port that otp_enc should attempt to connect to otp_enc_d on
 otp_dec <ciphertext> <key> <port>
 - ciphertext is the name of a file in the current directory that contains the ciphertext you wish to decrypt.
 - key contains the encryption key you wish to use to decrypt the text.
 - port is the port that otp_dec should attempt to connect to otp_dec_d on
 

