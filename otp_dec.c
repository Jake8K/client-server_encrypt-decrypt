/*****************************************************************************************
 * Author: 	Jacob Karcz
 * Date: 	3.18.2017 
 * Course:	CS344-400: Intro to Operating Systems
 * Program 4: 	otp_dec.c 
 * Description: This program connects to otp_dec_d and asks it to perform a one-time pad
 * 		style decryption. It validates if the ciphertext or key files contain bad
 * 		characters and verifies that the key is at least as long as the ciphertext.
 * 		otp_dec should not be able to connect to otp_enc_d. If this happens, 
 * 		otp_dec will report the rejection, then terminate. When otp_dec receives
 * 		the plaintext back from otp_dec_d it will output it to stdout. 
******************************************************************************************/


/* headers
 ------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include <fcntl.h> //open files
#include <errno.h>
#include <assert.h>
#include <signal.h>

/* constants
 ------------*/
#define BUFFER_SIZE    2000 //socket buffer
#define DEBUG          0

/* booleans!
 ------------*/
enum bool { true, false };
typedef enum bool bool;


 /* Functions 
  ----------------------------*/
int checkFile(int FD);
void error(const char *msg);
int sendFile(int fileFD, int socketFD, int fileSize);
int secretHandshake(int connectionFD, char* serverProcess, char* clientProcess);


/************************************************************
  * int main(int, char*)
 ************************************************************/
int main(int argc, char *argv[]) {

	//variabales
	int socketFD, 
	    portNumber, 
	    charsWritten, 
	    charsRead,
	    verifyConnect;
	int msgFD,
	    keyFD,
	    msgChars,
	    keyChars,
	    terminalLocation;

	char buffer[BUFFER_SIZE];	

	struct sockaddr_in serverAddress;

	struct hostent* serverHostInfo;
    
	
	if (argc < 4) { fprintf(stderr,"USAGE: %s <message file> <cipher key file> <port>\n", argv[0]); exit(0); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	//serverHostInfo = gethostbyname(argv[1]); // Convert the machine name into a special form of address
	serverHostInfo = gethostbyname("localhost");
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

	//verify server ID
	verifyConnect = clientHandshake(socketFD, "otp_dec_d", "otp_dec");
	if(DEBUG) {printf("verify connect = %d\n", verifyConnect);}
	if (verifyConnect != 0) {
		if(verifyConnect == 1) {error("could not verify identity of otp_dec_d. process terminating\n");}
		exit(1);
	}
	if(DEBUG){ printf("otp_dec_d connection verified\n"); }		
	
	//OPEN THE FILES AND DO STUFF
	//open the files
	msgFD = open(argv[1], O_RDONLY);
	if (msgFD < 1) {
		fprintf(stderr, "error opening %s\n", argv[1]);
		exit(1);
	}
	keyFD = open(argv[2], O_RDONLY);
	if (msgFD < 1) {
		fprintf(stderr, "error opening %s\n", argv[2]);
		exit(1);
	}


	//send the files
	msgChars = checkFile(msgFD);
	keyChars =checkFile(keyFD);
	sendFile(msgFD, socketFD, msgChars);
	sendFile(keyFD, socketFD, keyChars);
	if(DEBUG){ printf("otp_dec files sent\n"); }			


	//
	char decryption[msgChars];
		memset(decryption, '\0', sizeof(decryption)); 

	//charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, MSG_WAITALL);
	//if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	//fprintf(stdout, "%s\n", buffer);
	if(DEBUG){ printf("otp_dec waiting for decryption...\n"); }				
	while(strstr(buffer, "@@@") == NULL){
		memset(buffer, '\0', sizeof(buffer));
		charsRead =  recv(socketFD, buffer, sizeof(buffer)-1, 0);
		if (charsRead < 0) error("ERROR reading from socket");
		strcat(decryption, buffer);
	}
	if(DEBUG){ printf("otp_dec received decryption... processing sigil\n"); }					
	terminalLocation = strstr(decryption, "@@@") - decryption;
	decryption[terminalLocation] = '\0';
	if(DEBUG){ printf("otp_dec decrypted message:\n%s\n", decryption); }						
	//stdout the encryption
	//fprintf(stdout, "%s\n", decryption);
	printf("%s\n", decryption);	
	if(DEBUG){ printf("decrypted message send to stdout\n"); }					

	//close out
	close(msgFD);
	close(keyFD);
	close(socketFD); // Close the socket
	if(DEBUG){ printf("files and sockets closed\n"); }						
	return 0;
}

  /*************************************************************
  * file verification function
 ************************************************************/
int checkFile(int FD) {
	//variables
	int fileSize,
	    bytesRead,
	    i;
	char buffer[BUFFER_SIZE];
		memset(buffer, '\0', sizeof(buffer));
	
	//read to buffer
	bytesRead = read(FD, buffer, sizeof(buffer));

	//rewind the file
	int pos = lseek(FD, 0, SEEK_SET);

	/*-------------check the buffer------
	for (i = 0; i < bytesRead; i++) {
		if( (buffer[i] < 'A' || buffer[i] > 'Z') 
		  && buffer[i] != ' ' && buffer[i] != '\n') {
			return -1; //bad cookie
		}
	}---------------------------------------*/

	if(DEBUG){
		printf("checkFile()\nbytes read: %d\nbuffer: %s\n", bytesRead, buffer);
	}

	fileSize = lseek(FD, 0, SEEK_END);
	return fileSize;

}

/*************************************************************
 * file sending function 
 *************************************************************/
int sendFile(int fileFD, int socketFD, int fileSize) {
	
	//variables
	int bytesSent = 0,
	    bytesRead = 0,
	    bytesWritten = 0, 
	    sigilBytes = 0;
	char buffer[BUFFER_SIZE];
	char file[fileSize+5];
	memset(buffer, '\0', sizeof(buffer));
	memset(file, '\0', sizeof(file));
	if(DEBUG){ printf("otp_enc sendFile()\n"); }
	
	//rewind the file
	int pos = lseek(fileFD, 0, SEEK_SET);

	
	//read the file into the buffer
	bytesRead = read(fileFD, file, sizeof(file)-1);
	if(DEBUG){
		printf("bytes read: %d\nfile size: %d\nfile buffer: %s\n", bytesRead,fileSize, file);
	}
	//add the sigil
	strcat(file, "@@@\0");

	//rewind the file
	pos = lseek(fileFD, 0, SEEK_SET);


	//send the buffer
	while (bytesSent < (fileSize+5)){ 
		//part out the fileBuffer
		memset(buffer, '\0', sizeof(buffer));
		strncpy(buffer, &file[bytesSent], BUFFER_SIZE-1);
		
		//send
		//bytesWritten = send(socketFD, file, fileSize, 0);
		bytesWritten = send(socketFD, buffer, BUFFER_SIZE-1, 0);		
		if (bytesWritten < 0) error("ERROR writing to socket");

		//bytesSent += bytesWritten;
		bytesSent += (BUFFER_SIZE - 1);
		if(DEBUG){
			printf("\tbytes sent(now): %d\ntbytes sent(total): %d\nsend buffer: %s\n", bytesWritten, bytesSent, buffer);
		}

	}
	//sigilBytes = write(socketFD, "@@@\0", 4);	
	//bytesWritten = write(socketFD, buffer, bytesRead);   //sizeof(buffer)-1);
	if(DEBUG){
		printf("sendFile()\nbytes sent: %d\n", bytesSent);
	}

	if (bytesSent < bytesRead) {
		fprintf(stderr, "error sending to server, some bytes may have been lost\n");
		return 1;
	}
	return 0;

}

	
/****************************************************
 * package sending function
 ***************************************************/
int sendPackage(int fileFD, int socketFD) {
	//variables
	int bytesRead = 0,
	    bytesWritten = 0;
	bool packageSent = false;	
	void* placeHolder = 0;
	char buffer[BUFFER_SIZE];
		memset(buffer, '\0', sizeof(buffer)); 

	if(DEBUG) {printf("****\notp_dec sendPackage Function:\n"); }


	//rewind the file
	int pos = lseek(fileFD, 0, SEEK_SET);

	//send file
	while (!packageSent) {
		//read file data to the buffer and record the number of chars
		memset(buffer, '\0', sizeof(buffer)); 
		bytesRead = read(fileFD, buffer, sizeof(buffer)-1);
		if(DEBUG) {printf("%d\nbuffer:\n%s\n",bytesRead, buffer); }		
		if (bytesRead == 0)
			break;
		if (bytesRead < 0) {
			error("error reading from file");
		}

		//write the buffer to the socket
		//placeHolder  tracks where in the buffer we are
		//bytesRead is decremented to track how mnay bytes are left to write
		placeHolder = buffer;
		while(bytesRead > 0) {
			bytesWritten = write(socketFD, placeHolder, bytesRead);
			if(DEBUG) {printf("bytesWritten: %d, placeHolder: %d\n", bytesWritten, placeHolder); }			
			if(bytesWritten <= 0)
				error("error sending packet");
			bytesRead -= bytesWritten;
			placeHolder += bytesWritten;
		}
		if(bytesRead <= 0 && bytesWritten <= 0)
			packageSent = true;
	}
	if(DEBUG) {printf("bytesRead: %d\n", bytesRead);}	
	return bytesRead; // should be 0 if everything that was read was sent
}

/****************************************************
 * package receiving function
 ***************************************************/
int getPackage(int socketFD, char* package) {
	//variables
	int bytesRead = 0;
	int packageBytes = 0;
	bool packageReceived = false;
	char buffer[BUFFER_SIZE];
		memset(buffer, '\0', sizeof(buffer));
		
	if(DEBUG) {printf("****\notp_dec getPackage Function:\n"); }

	while (!packageReceived) {
		//read data from the socket
		memset(buffer, '\0', sizeof(buffer));
		bytesRead = 0;
		bytesRead = recv(socketFD, buffer, sizeof(buffer)-1, 0);
		if(DEBUG) {printf("%d\nbuffer:\n%s\n",bytesRead, buffer); }
		packageBytes += bytesRead;
		if (bytesRead < 0) {
			error("error reading from socket");
		}
		//save the buffer contents 
		if (bytesRead > 0) {
			strcat(package, buffer);
			if(DEBUG) {printf("%d\nstrcatResults:\n%s\n",bytesRead, package); }						
		}
		if (bytesRead == 0)
			packageReceived = true;

	}
	if(DEBUG) {printf("packageBytes: %d\n", packageBytes);}
	return packageBytes;
}

/****************************************************
 * process connection verification function
 ***************************************************/
int clientHandshake(int connectionFD, char* serverProcess, char* clientProcess) {
	//variables
	int charsRead;
	char buffer[128];
		memset(buffer, '\0', sizeof(buffer));
		
	//send client ID
	send(connectionFD, clientProcess, strlen(clientProcess), 0);

	//read server ID
	charsRead = recv(connectionFD, buffer, sizeof(buffer)-1, 0);
	if (charsRead < 0) { error("error reading server ID, terminating connection."); return 2;}

	if(strncmp(buffer, serverProcess, charsRead) == 0) {
		return 0; //ID verified
	}
	else {
		return 1; //wrong ID
	}	
}




 /* Error Reporting Functions
 ************************************************************/
void error(const char *msg) { perror(msg); exit(1); } 

