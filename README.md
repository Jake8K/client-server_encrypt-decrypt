# client-server_encrypt-decrypt

File encryption and description in c, encrypting or decrypting server will encrypt/decrypt the file submitted by the client<br />

Enter "compilall" to compile the 2 server and client programs and the key generator<br />

Key generator usage:<br />
  keygen <keylength> [ > mykeyfile ]<br />
  -keylength is the length of the key file in characters. keygen outputs to stdout<br />
  
Server usage:<br />
 otp_enc_d <listening_port> [&]<br />
 otp_dec_d <listening_port> [&]<br />

Client usage:<br />
 otp_enc <plaintext> <key> <port><br />
 - plaintext is the name of a file in the current directory that contains the plaintext you wish to encrypt.<br />
 - key contains the encryption key you wish to use to encrypt the text.<br />
 - port is the port that otp_enc should attempt to connect to otp_enc_d on<br />
 otp_dec <ciphertext> <key> <port><br />
 - ciphertext is the name of a file in the current directory that contains the ciphertext you wish to decrypt.<br />
 - key contains the encryption key you wish to use to decrypt the text.<br />
 - port is the port that otp_dec should attempt to connect to otp_dec_d on<br />
 

