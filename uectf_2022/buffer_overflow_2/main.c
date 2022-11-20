#include <stdio.h>
#include <unistd.h>

void vuln() {
    char buf[0x60];
    printf("> ");
    read(STDIN_FILENO, buf, 0x80);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    vuln();
    puts("Bye!");
    return 0;
}
