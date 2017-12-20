/*****************************************************************************************
 * Author: 	Jacob Karcz
 * Date: 	3.18.2017 
 * Course:	CS344-400: Intro to Operating Systems
 * Program 4: 	keygen.c 
 * Description: This program creates a key file of specified length to be used in the 
 * 		one-time pad encryption/decryption.  The characters in the file generated
 * 		will be any of the 27 allowed characters (A-Z and ' '). The final character
 * 		in the key file will be the newline character.
 * ******************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>


/************************************************************
  * int main(int, char*)
 ************************************************************/

int main (int argc, char *argv[]) {

	//variables
	int i, 
	    key, 
	    keyLength;

	//check usage
	if (argc != 2) {
		fprintf(stderr, "not enough arguements\nUsage: keygen <keylength>");
		exit(1);
	}

	//create key
	srand(time(0));
	keyLength = atoi(argv[1]);
	for(i = 0; i < keyLength; i++) {
		key = rand() % 27;
		if (key < 26) {
			printf("%c", 'A'+(char)key);
		}
		else{
			printf("%c", ' ');
		}
	}
	printf("%c", '\n');
	

	return 0;
}
