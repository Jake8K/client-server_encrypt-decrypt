/*****************************************************************************************
 * Author: 	Jacob Karcz
 * Date: 	3.18.2017 
 * Course:	CS344-400: Intro to Operating Systems
 * Program 4: 	otp_dec_d.c 
 * Description:	This program will run in the background as a daemon. It's function is to 
 * 		perform decryption using a one-time pad-like system.  It listens on a 
 * 		particular port/socket and when a connection is made another socket is
 * 		created for communication.  It can support up to 5 concurrent socket
 * 		connections. After making sure it is communicating with otp_dec it receives 
 * 		ciphertext and a key via the same communication socket. After decryption the 
 * 		plaintext is sent back to otp_dec.   
 *******************************************************************************************/


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
#define BUFFER_SIZE    200000 //file buffer
#define DEBUG          0

/* booleans!
 ------------*/
enum bool { true, false };
typedef enum bool bool;


/* Functions
 ----------------------------*/
void exitError(const char *msg);
void error(const char *msg); 
int decryptMsg(char* message, char* cipher, int msgLength);
int serverHandshake(int connectionFD, char* clientProcess, char* serverProcess);
int getPackage(int socketFD, char* package);
void zombies();


/************************************************************
  * int main(char* otp_dec_d, int portNumber)
 ************************************************************/
int main(int argc, char *argv[]) {

	//variables
	int i, 
	    listenSocketFD, 
	    establishedConnectionFD, 
	    portNumber,
	    msg_charsRead,
	    key_charsRead,
	    sent_charsRead,
	    verifyConnect, 
	    msgSize,
	    keySize,
	    terminalLocation;
	int spawnPID = -18;
	int exitStat = -18;
	
	char buffer[2000]; //200000 <–––––––– the key to sending the right section of the longass key
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
	if (argc < 2) { fprintf(stderr,"USAGE: %s <port>\n", argv[0]); exit(1); } 


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
	if(DEBUG) {printf("otp_dec_d pid: %d\n", getpid());}
	while(1) {
		if (spawnPID != 0) {
			// Accept a connection, blocking if one is not available until one connects
			sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
			establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
			if (establishedConnectionFD < 0) error("ERROR on accept");

			verifyConnect = serverHandshake(establishedConnectionFD, "otp_dec", "otp_dec_d");
			if (verifyConnect == 0) {
				spawnPID = fork(); 
				if (spawnPID < 0) { error("otp_dec_d: error forking child process\n"); }
			}
			else if(verifyConnect == 1) {
				if(DEBUG) {error("error recognizing otp_dec's authorization. connection refused.\n");}
			}
			

		}

		if (spawnPID == 0) {
			if(DEBUG) {printf("otp_dec_d ppid: %d, pid: %d\n", getppid(), getpid());}

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
			//while(1){
				memset(buffer, '\0', sizeof(buffer));
				key_charsRead =  recv(establishedConnectionFD, buffer, sizeof(buffer)-1, 0);
				if (key_charsRead < 0) error("ERROR reading from socket");
				if(DEBUG) {printf("key bytes: %d\nkey buffer:\n%s\n", key_charsRead, buffer);}
				strcat(keyBuffer, buffer);
				if(DEBUG) {printf("key(so far):\n%s\n", keyBuffer);}
				if(strstr(keyBuffer, "@@@") != NULL) {break;}					//NEW			
				
			}
			terminalLocation = strstr(keyBuffer, "@@@") - keyBuffer;
			keyBuffer[terminalLocation] = '\0';
			//key_charsRead = recv(establishedConnectionFD, keyBuffer, BUFFER_SIZE-1, MSG_WAITALL);
			if(DEBUG) {printf("SERVER: I received this key from the client: \"%s\"\n", keyBuffer);}
			keySize = strlen(keyBuffer);
			

			//encrypt the message
			decryptMsg(msgBuffer, keyBuffer, msgSize);
		       	if(DEBUG) {printf("SERVER: This is the decrypted message: \"%s\"\n", msgBuffer);}
			
			//send the encrypted message
			i = 0;
			while (i < msgSize){ 
				sent_charsRead = send(establishedConnectionFD, msgBuffer, msgSize, 0);
				if (sent_charsRead < 0) error("ERROR writing to socket");
				i += sent_charsRead;
		       		if(DEBUG) {printf("SERVER: sending encryption, %d chars sent, %d total (%d total size)\n", sent_charsRead, i, msgSize);}

			}
			int sigilBytes = write(establishedConnectionFD, "@@@\0", 4);
		       	if(DEBUG) {printf("SERVER: message successfully sent to client");}

			/*------ Old Code -----*

			// Get the message from the client and display it
			memset(msgBuffer, '\0', BUFFER_SIZE);
			msg_charsRead = recv(establishedConnectionFD, msgBuffer, BUFFER_SIZE-1, 0); // Read the client's message from the socket
			if (msg_charsRead < 0) error("ERROR reading from socket");
			if(DEBUG) {printf("SERVER: I received this message from the client: \"%s\"\n", msgBuffer);}
			if (msgBuffer[strlen(msgBuffer)-1] == '\n')  {msgBuffer[strlen(msgBuffer)-1] = '\0';} //remove trailing '\n'			
			
			// Get the key from the client and display it
			memset(keyBuffer, '\0', BUFFER_SIZE);
			key_charsRead = recv(establishedConnectionFD, keyBuffer, BUFFER_SIZE-1, 0); // Read the client's message from the socket
			if (key_charsRead < 0) error("ERROR reading from socket");
			if(DEBUG) {printf("SERVER: I received this key from the client: \"%s\"\n", keyBuffer);}


			//decrypt the message
			decryptMsg(msgBuffer, keyBuffer, msg_charsRead);
		       	if(DEBUG) {printf("SERVER: This is the decrypted message: \"%s\"\n", msgBuffer);}	
			//
			//send the encrypted message
			sent_charsRead = send(establishedConnectionFD, msgBuffer, msg_charsRead, 0); // Send success back
			if (sent_charsRead < 0) error("ERROR writing to socket");
			*--------old -------*/

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
 * Decrypting function
 *************************************************************/
int decryptMsg(char* message, char* cipher, int msgLength) {
	//ascii stuff
	//A-Z == 65-90 ~= 0-25
	//' ' == 32 ~= 26

	//vars
	int i,
	    msgAscii,
	    keyAscii,
	    decryptAscii;
	int keyChars = 27; //'A'-'Z' + ' '

	for (i= 0; i < msgLength-1; i++) {
		if(message[i] != '\n') {
			//get message char
			if(message[i] == ' ') {
				msgAscii = 26;
			}
			else {
				msgAscii = (int)message[i] - 'A';
			}
			//get cipher char
			if(cipher[i] == ' ') {
				keyAscii = 26;
			}
			else {
				keyAscii = cipher[i] - 'A';
			}
			//deccrypt the char
			decryptAscii = (msgAscii - keyAscii);
		        if(decryptAscii < 0) {
				decryptAscii += 27; 
			}
			decryptAscii %= keyChars;
			if(decryptAscii == 26) {
				message[i] = 32; // ' '
			}
			else {
				message[i] = 'A' + (char)decryptAscii;
			}
		}
	}
	
	return 0;
}

//if(ciphervalue <= 0)
//	ciphervalue = ciphervalue + 27;


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
//	if (charsRead < 0) { error("error reading client ID, terminating connection."); return 2;}

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
 * function to reap bakground child zombie processes 
 ***************************************************/
void reapZombies(pid_t zombies[], int* numZombies) {
	int i = 0;
	int exitStat;
	int deadZombies = 0;
	pid_t zombieChild;
	for(i = 0; i < *numZombies; i++) {
		zombieChild = waitpid(zombies[i], &exitStat, WNOHANG);
		if (zombieChild > 0 ) {
			deadZombies++;
			printf("background pid %d is done: ", zombieChild);
			fflush(stdout);	
			if (WIFEXITED(exitStat)) { //exitStat
				printf("exit value %d\n", WEXITSTATUS(exitStat));
				fflush(stdout);
			}
			else if (WIFSIGNALED(exitStat)) { //sigStat
				printf("terminated by signal %d\n", WTERMSIG(exitStat));
				fflush(stdout);
			}
		}
	}
	*numZombies -= deadZombies;
}

/****************************************************
 * SIGCHILD signal handler function
 ***************************************************/
void zombies() {
	int exitStat;
	pid_t zombieChild;

	zombieChild = waitpid(-1, &exitStat, WNOHANG);
}

	
	




/*-------------- testing grounds --------------------*
 *
 *--------------------KEY---------------------------*
 
 YQPFSBKL IJVPNRSORJMHGLVCJCKQKGNQKHXLSIKPRVDTLLXBUIYATSCBUBGTXU...
 
89 81

 *-------------------ORIGINAL------------------------*

 THE RED GOOSE FLIES AT MIDNIGHT STOP



 
 *-------------------Encrypted------------------------*

 QXTEIFNKFWXMTMWCWVALHZKGKMPSWRZMHCVL
 


 *-------------------Decrypted------------------------*

 9HE@7ED@,OO8E@F1IE8@AT@2IDNIGHT@89O5


 *----------------------------------------------------*/ 
