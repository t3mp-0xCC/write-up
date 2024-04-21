#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void init(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	alarm(60);
}

int main() {
	init();

	char buf[5] = "";
	int length = 0;
	char flag[100] = "";

	FILE *fp = fopen("flag.txt", "r");
	if (fp == NULL) {
		puts("flag.txt does not exist.");
		return 1;
	}
	fgets(flag, 100, fp);
	fclose(fp);

	printf("Please enter some string! (max 4 character)\n");
	read(0, buf, 5);
	for (int i = 0; i < 4; i++) {
		if (buf[i] == '\n') {
			buf[i] = '\0';
			break;
		}
	}
	buf[4] = '\0';

	printf("Thank you!\nYour input:");
	length = printf(buf);
	printf("\n");
	printf("Length: %d\n", length);

	printf("This is your reward!\n");

	for (int i = 0; i < length; i++) {
		printf("%c", flag[i]);
		if(i >= strlen(flag)) {
			break;
		}
	}
	printf("\n");

	return 0;
}
