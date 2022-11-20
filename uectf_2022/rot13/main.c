#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NUM 8
#define BUF_SIZE 0x20

char **list;

int get_num(char *msg) {
    int n;

    printf("%s", msg);
    scanf("%d%*c", &n);
    return n;
}

void create() {
    int index = get_num("index: ");
    if(index >= MAX_NUM) {
        puts("Invalid!");
        exit(EXIT_FAILURE);
    }

    char *buf, *p;
    printf("data: ");
    buf = malloc(BUF_SIZE);
    buf[read(STDIN_FILENO, buf, BUF_SIZE-1)] = '\0';
    if((p = strrchr(buf, '\n')))
        *p = '\0';
    list[index] = buf;
}

void run() {
    int index = get_num("index: ");
    if(index >= MAX_NUM || list[index] == NULL) {
        puts("Invalid!");
        exit(EXIT_FAILURE);
    }

    char *buf = list[index];
    for(; *buf; buf++) {
        char c = *buf;
        if(c >= 'a' && c <= 'z')
            *buf = (c - 'a' + 13) % 26 + 'a';
        else if(c >= 'A' && c <= 'Z')
            *buf = (c - 'A' + 13) % 26 + 'A';
        else
            *buf = c;
    }
    puts("Done!");
}

void show() {
    int index = get_num("index: ");
    if(index >= MAX_NUM) {
        puts("Invalid!");
        exit(EXIT_FAILURE);
    }
    puts(list[index]);
}

void edit() {
    int index = get_num("index: ");
    if(index >= MAX_NUM || list[index] == NULL) {
        puts("Invalid!");
        exit(EXIT_FAILURE);
    }

    char *buf, *p;
    printf("data: ");
    buf = list[index];
    buf[read(STDIN_FILENO, buf, BUF_SIZE-1)] = '\0';
    if((p = strrchr(buf, '\n')))
        *p = '\0';
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char *name = malloc(BUF_SIZE);
    printf("name: ");
    scanf("%10s", name);
    printf("Hello %s!\n", name);
    free(name);

    list = calloc(MAX_NUM, sizeof(char *));

    puts("1. create");
    puts("2. run");
    puts("3. show");
    puts("4. edit");
    puts("5. exit");

    while(1) {
        int choice = get_num("> ");
        switch(choice) {
            case 1:
                create();
                break;
            case 2:
                run();
                break;
            case 3:
                show();
                break;
            case 4:
                edit();
                break;
            default:
                puts("Bye!");
                exit(EXIT_SUCCESS);
        }
    }
    return 0;
}
