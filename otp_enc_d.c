/*****************************************************************************************
 * Author: 	Jacob Karcz
 * Date: 	3.18.2017 
 * Course:	CS344-400: Intro to Operating Systems
 * Program 4: 	otp_enc_d.c 
 * Description:	This program will run in the background as a daemon. It's function is to 
 * 		perform encryption using a one-time pad-like system.  It listens on a 
 * 		particular port/socket and when a connection is made another socket is
 * 		created for communication.  It can support up to 5 concurrent socket
 * 		connections. After making sure it is communicating with otp_enc it receives 
 * 		plaintext and a key via the same communication socket. After encryption the 
 * 		ciphertext is sent back to otp_enc.  
 ******************************************************************************************/



/* headers
 ------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <fcntl.h> //open files
#include <errno.h>
#include <assert.h>
#include <signal.h>

/* constants
 ------------*/
#define BUFFER_SIZE    200000 //for files
#define DEBUG          0

/* booleans!
 ------------*/
enum bool { true, false };
typedef enum bool bool;


/* Functions
 ----------------------------*/
void exitError(const char *msg);
void error(const char *msg); 
int encryptMsg(char* message, char* cipher, int msgLength);
int serverHandshake(int connectionFD, char* clientProcess, char* serverProcess);
int getPackage(int socketFD, char* package);
void zombies();


/************************************************************
  * int main(int, char*)
 ************************************************************/
int main(int argc, char *argv[]) {

	//variables
	int i,
	    listenSocketFD, 
	    establishedConnectionFD, 
	    portNumber,
	    msg_charsRead,
	    key_charsRead,
	    msgSize,
	    keySize,
	    sent_charsRead,
	    terminalLocation,
	    verifyConnect;
	int spawnPID = -18;
	int exitStat = -18;	

	char buffer[2000];     // <–––––––– the key to sending the right section of the longass key (with a huge buffer, sometimes)
	char msgBuffer[BUFFER_SIZE];
	char keyBuffer[BUFFER_SIZE];

	struct sockaddr_in serverAddress, 
			   clientAddress;

	socklen_t sizeOfClientInfo;

	//handle dead children
	struct sigaction zombieSig,
			 zombieSig_O;
	zombieSig.sa_handler = zombies;
	zombieSig.sa_flags = SA_RESTART;
	sigaction(SIGCHLD, &zombieSig, &zombieSig_O); 

	//check usage & args
	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } 


	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) exitError("ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		exitError("ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	//begin infinite looping
	//
	if(DEBUG) {printf("otp_enc_d pid: %d\n", getpid());}
	while(1) {
		if (spawnPID != 0) {
			// Accept a connection, blocking if one is not available until one connects
			sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
			establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
			if (establishedConnectionFD < 0) error("ERROR on accept");

			verifyConnect = serverHandshake(establishedConnectionFD, "otp_enc", "otp_enc_d");
			if (verifyConnect == 0) {
				spawnPID = fork(); 
				if (spawnPID < 0) { error("otp_enc_d: error forking child process\n"); }
			}
			else if(verifyConnect == 1) {
				if(DEBUG) {error("error recognizing process authorization. connection refused.\n");}
			}
			// don't forget to kill the zombie children --> (using SIGCHILD)						
		}

		if (spawnPID == 0) {

			if(DEBUG) {printf("otp_enc_d ppid: %d, pid: %d\n", getppid(), getpid());}
			
			// Get the message from the client and display it
			memset(msgBuffer, '\0', sizeof(msgBuffer));			
			while(strstr(buffer, "@@@") == NULL){
				memset(buffer, '\0', sizeof(buffer));
				msg_charsRead =  recv(establishedConnectionFD, buffer, sizeof(buffer)-1, 0);
				if (msg_charsRead < 0) error("ERROR reading from socket");
				strcat(msgBuffer, buffer);
			}
			terminalLocation = strstr(msgBuffer, "@@@") - msgBuffer;
			msgBuffer[terminalLocation] = '\0';
			//msg_charsRead = recv(establishedConnectionFD, msgBuffer, BUFFER_SIZE-1, MSG_WAITALL); 
			//if (msg_charsRead < 0) error("ERROR reading from socket");
			if (msgBuffer[strlen(msgBuffer)-1] == '\n')  {msgBuffer[strlen(msgBuffer)-1] = '\0';} //remove trailing '\n'		
			if(DEBUG) {printf("SERVER: I received this message from the client: \"%s\"\n", msgBuffer);}
			msgSize = strlen(msgBuffer);
			
			
			// Get the key from the client and display it
			memset(buffer, '\0', sizeof(buffer));
			memset(keyBuffer, '\0', sizeof(keyBuffer));
			while(strstr(buffer, "@@@") == NULL){							//NEW
//			while(1){
				memset(buffer, '\0', sizeof(buffer));
				key_charsRead =  recv(establishedConnectionFD, buffer, sizeof(buffer)-1, 0);
				if (key_charsRead < 0) error("ERROR reading from socket");
				if(DEBUG) {printf("key bytes: %d\nkey buffer:\n%s\n", key_charsRead, buffer);}
				strcat(keyBuffer, buffer);
				if(DEBUG) {printf("key(so far):\n%s\n", keyBuffer);}
				if(strstr(buffer, "@@@") != NULL) {break;}					//NEW			
			}
			terminalLocation = strstr(keyBuffer, "@@@") - keyBuffer;
			keyBuffer[terminalLocation] = '\0';
			//key_charsRead = recv(establishedConnectionFD, keyBuffer, BUFFER_SIZE-1, MSG_WAITALL);
			if(DEBUG) {printf("SERVER: I received this key from the client: \"%s\"\n", keyBuffer);}
			keySize = strlen(keyBuffer);
			

			//encrypt the message
			encryptMsg(msgBuffer, keyBuffer, msgSize);
		       	if(DEBUG) {printf("SERVER: This is the encrypted message: \"%s\"\n", msgBuffer);}
			
			//send the encrypted message
			i = 0;
			while (i < msgSize){ 
				sent_charsRead = send(establishedConnectionFD, msgBuffer, msgSize, 0);
				if (sent_charsRead < 0) error("ERROR writing to socket");
				i += sent_charsRead;
			}
			int sigilBytes = write(establishedConnectionFD, "@@@\0", 4);
			//sent_charsRead = send(establishedConnectionFD, msgBuffer, msgSize, 0);
			//if (sent_charsRead < 0) error("ERROR writing to socket");
			if(DEBUG) {printf("encryption sent successfully\n");}
			
			
			// Close the existing socket connected to the client
			close(establishedConnectionFD);

			return 0;
		}
	}

	close(listenSocketFD); // Close the listening socket
	return 0; 
}

/************************************************************
 * Error Reporting Functions
 ************************************************************/
void exitError(const char *msg) { perror(msg); exit(1); } 
void error(const char *msg) { perror(msg); }


/************************************************************
 * Encrypting function
 *************************************************************/
int encryptMsg(char* message, char* cipher, int msgLength) {
	//ascii stuff
	//A-Z == 65-90 ~= 0-25
	//' ' == 32 ~= 26

	//vars
	int i,
	    msgAscii,
	    keyAscii,
	    encryptAscii;
	int keyChars = 27; //'A'-'Z' + ' '

	for (i= 0; i < msgLength-1; i++) {
		if(message[i] != '\n') {
			//get message char
			if(message[i] == ' ') {
				msgAscii = 26;
			}
			else {
				msgAscii = message[i] - 'A';
			}
			//get cipher char
			if(cipher[i] == ' ') {
				keyAscii = 26;
			}
			else {
				keyAscii = cipher[i] - 'A';
			}
			//encrypt the char
			encryptAscii = (msgAscii + keyAscii) % keyChars;
			if(encryptAscii == 26) {
				message[i] = ' ';
			}
			else {
				message[i] = 'A' + (char)encryptAscii;
			}
		}
	}
	
	return 0;
}

/****************************************************
 * process connection verification function
 ***************************************************/
int serverHandshake(int connectionFD, char* clientProcess, char* serverProcess) {
	//variables
	int charsRead;
	char buffer[128];
		memset(buffer, '\0', sizeof(buffer));
	
	//read client ID
	charsRead = recv(connectionFD, buffer, sizeof(buffer)-1, 0); 
	if (charsRead < 0) { error("error reading client ID, terminating connection."); return 2;}

	//send server ID
	send(connectionFD, serverProcess, strlen(serverProcess), 0);

	
	//verify ID
	if(strncmp(buffer, clientProcess, charsRead) == 0) {
		return 0; //ID verified
	}
	else {
		return 1; //wrong ID
	}
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
 * package sending function
 ***************************************************
int endEncryption(char* message, int socketFD) {
	//variables
	int bytesRead = 0,
	    bytesWritten = 0;
	void* placeHolder = 0;
	char buffer[BUFFER_SIZE];
		memset(buffer, '\0', sizeof(buffer)); 

	while (1) {
		//read data to the buffer and record the number of chars
		memset(buffer, '\0', sizeof(buffer)); 
		bytesRead = read(fileFD, buffer, sizeof(buffer)-1);
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
			if(bytesWritten <= 0)
				error("error sending packet");
			bytesRead -= bytesWritten;
			placeHolder += bytesWritten;
		}
	}// i can probably erase this because I won't be using it....
}
---------probably not using this (incomplete)-------------*/

		



/****************************************************
 * SIGCHILD signal handler function
 ***************************************************/
void zombies() {
	int exitStat;
	pid_t zombieChild;

	zombieChild = waitpid(-1, &exitStat, WNOHANG);
}

	
	

