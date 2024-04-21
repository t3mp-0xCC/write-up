#include <stdio.h>
#include <stdlib.h>

int enemyHp, playerHp;
void (*win)();
void (*enemyCommand)();
void (*playerCommands[3])();

void init(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	alarm(60);
}

void getFlag(){
	puts("You got the flag!");
	system("cat flag.txt");
}

void hocusPocus(){
	puts("Memory leak!");
	printf("Attack     : %p\n", &playerCommands[0]);
	printf("Heal       : %p\n", &playerCommands[1]);
	printf("HocusPocus : %p\n", &playerCommands[2]);
	printf("win        : %p\n\n", &win);
}

void attack(){
	enemyHp -= 40;
	if(enemyHp < 0){
		enemyHp = 0;
	}
}

void heal(){
	playerHp += 30;
	if(playerHp > 100){
		playerHp = 100;
	}
}

void enemyAttack(){
	playerHp -= 50;
	if(playerHp < 0){
		playerHp = 0;
	}
}

void printHp(){
	printf("YourHP:%d\nenemyHp:%d\n\n", playerHp, enemyHp);
}

void printCommands(){
	puts("1: Attack\n2: Heal\n3: Hocus Pocus\n");
}

int main(){
	int input;

	init();
	enemyHp = 100;
	playerHp = 100;
	playerCommands[0] = attack;
	playerCommands[1] = heal;
	playerCommands[2] = hocusPocus;
	enemyCommand = enemyAttack;
	win = getFlag;

	puts("\n");
	puts("Defeat the enemy to get the flag!\n\n");

	while(1){
		printHp();
		if(playerHp <= 0){
			puts("You lose...");
			break;
		}else if(enemyHp <= 0){
			win();
		}
		printCommands();

		scanf("%d", &input);
		printf("\n");

		if(input > 3){
			puts("Nothing happens.\n");
		}else{
			playerCommands[input - 1]();
		}
		enemyCommand();
	}
	return 0;
}
