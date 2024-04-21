#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#define BUF_SIZE 16

int init(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	alarm(60);

	return 0;
}

int win() {
	system("cat flag.txt");

	return 0;
}

int main() {
	init();

	char buf[BUF_SIZE];

	printf("input:");
	gets(buf);

	if(strlen(buf) > BUF_SIZE) {
		printf("Too long.\n");
		exit(0);
	}

	return 0;
}
