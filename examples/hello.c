#include <stdio.h>
#include <string.h>

int main(void) {
    char message[64];
    snprintf(message, sizeof(message), "ELFscope fixture");
    puts(message);
    return 0;
}
