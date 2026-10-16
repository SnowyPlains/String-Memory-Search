#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv) {
    (void)argv;
    
    if (argc > 1) {
        printf("This program doesn't require arguments!\n");

        return -1;
    }

    char* secretString = "API_KEY = Hello Everyone!";
    char* secretString2 = "API_KEY2 = Secret API";
    char* secretString3 = "hxxps:\\\\SecretWebsite.com";

    printf("Process ID: %lu\n", GetCurrentProcessId());
    printf("Secret String is: %s\n", secretString);
    printf("Secret String is: %s\n", secretString2);
    printf("Secret String is: %s\n", secretString3);

    getchar();

    return 0;
}