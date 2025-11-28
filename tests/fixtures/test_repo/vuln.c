#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void processInput(const char* input) {
    char buffer[10];
    strcpy(buffer, input);  // VULNERABLE: Buffer overflow
}

void execute_command(const char* cmd) {
    system(cmd);  // VULNERABLE: Command injection
}
