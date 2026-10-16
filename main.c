#define _WIN32_WINNT 0x0A00

#include <stdio.h>
#include <windows.h>
#include <wow64apiset.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Program usage: .\\ProgramName.exe <pid> \"string To Search\"\n");

        return -1;
    }

    if (argc > 3) {
        printf("Too Many Arguments!\nProgram usage: .\\ProgramName.exe <pid> \"string To Search\"\n");

        return -1;
    }

    char* endPtr;
    errno = 0;

    long pid = strtol(argv[1], &endPtr, 10);

    if (endPtr == argv[1]) {
        printf("PID should not be a string! Please provide a number!\n");

        return 0;
    }

    if (*endPtr != '\0') {
        printf("PID is a full number, some trailing characters were found!\n");

        return -1;
    }

    if (errno == ERANGE) {
        printf("PID is too large! Please provide a real PID!\n");

        return -1;
    }

    if (pid < 0) {
        printf("PID is not a negative number!\n");

        return -1;
    }

    if (strcmp(argv[2], "") == 0) {
        printf("The string can't be empty!\n");

        return -1;
    }

    printf("\n==========================================================================================\n");
    printf("                                  Memory String Searcher                                  ");
    printf("\n==========================================================================================\n");

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (processHandle == NULL) {
        printf("Couldn't get a Handle to the Process! Error Code: %lu\n", GetLastError());

        return -1;
    }

    printf("\nTarget PID: %ld\n", pid);
    printf("String to Search: %s\n", argv[2]);

    printf("Target Process Architecture: ");
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    
    if (!IsWow64Process2(processHandle, &processMachine, &nativeMachine)) {
        printf("Couldn't determine the architecture of the program!\n");

        return -1;
    }

    USHORT targetMachine = processMachine;
    BOOL is64 = FALSE;
    BOOL is32 = FALSE;

    if (targetMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
        targetMachine = nativeMachine;
    }

    if (targetMachine == IMAGE_FILE_MACHINE_I386) {
        is64 = FALSE;
        is32 = TRUE;

        printf("32-bit\n");
    } else if (targetMachine == IMAGE_FILE_MACHINE_AMD64) {
        is64 = TRUE;
        is32 = FALSE;

        printf("64-bit\n");
    } else {
        printf("Unknown!\n");

        return -1;
    }
    printf("--------------------------------------------\n");

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t memoryAddress = 0x0;
    unsigned long long memoryLimit;

    if (is32) {
        memoryLimit = 0x7FFFFFFF;
    } else if (is64) {
        memoryLimit = 0x00007FFFFFFFFFFF;
    }

    unsigned int regionsScanned = 0;
    unsigned int matchesFound = 0;
    unsigned long long committedRegionsSize = 0;

    char* regionMemory = NULL;
    size_t bytesRead = 0;
    printf("\nScanning Memory Regions..");
    while ((VirtualQueryEx(processHandle, (LPCVOID)memoryAddress, &mbi, sizeof(mbi))) != 0 && memoryAddress < memoryLimit) {        
        if (mbi.State != MEM_COMMIT) {
            memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            
            continue;
        }

        if (mbi.Protect & PAGE_GUARD) {
            memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

            continue;
        }

        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {
            memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

            continue;
        }

        regionsScanned++;
        committedRegionsSize += mbi.RegionSize;

        if (regionMemory == NULL) {
            regionMemory = malloc(mbi.RegionSize);
        } else {
            char* temp = realloc(regionMemory, mbi.RegionSize);
        
            if (temp == NULL) {
                printf("Couldn't reallocate memory! Skipping the region\n");

                memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

                continue;
            }

            regionMemory = temp;
        }
        
        if ((ReadProcessMemory(processHandle, mbi.BaseAddress, regionMemory, mbi.RegionSize, &bytesRead)) == 0) {
            printf("Couldn't read Memory! Skipping the region!\n");

            memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

            continue;
        }

        if (bytesRead == 0) {
            printf("Read 0 bytes from this reagion!\n");

            memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

            continue;
        }

        size_t stringToSearchLength = strlen(argv[2]);

        if (bytesRead >= stringToSearchLength) {
            for (size_t i = 0; i <= (bytesRead - stringToSearchLength); i++) {
                if (memcmp((char*)regionMemory + i, argv[2], stringToSearchLength) == 0) {
                    uintptr_t stringFoundAddress = (uintptr_t)mbi.BaseAddress + i;
                    matchesFound++;
                    printf("\n    Match #%u\n", matchesFound);
                    printf("    - Match Found at Address: 0x%llX\n", stringFoundAddress);

                    // Scanning Backwards
                    size_t startOffset = i;
                    while (startOffset > 0)
                    {
                        char c = ((char*)regionMemory)[startOffset - 1];

                        if (!isprint((unsigned char)c) || c == '\0') {
                            break;
                        }

                        startOffset--;
                    }

                    // Scanning Forward
                    size_t endOffset = i + stringToSearchLength;
                    while (endOffset < bytesRead) {
                        char c = ((char*)regionMemory)[endOffset];

                        if (!isprint((unsigned char)c) || c == '\0') {
                            break;
                        }

                        endOffset++;
                    }
                    
                    size_t fullStringLength = endOffset - startOffset;
                    uintptr_t fullStringAddress = (uintptr_t)mbi.BaseAddress + startOffset;

                    printf("    - Full String Address: 0x%p\n", (void*)fullStringAddress);
                    printf("    - Full String: %.*s\n", (int)fullStringLength, (char*)regionMemory + startOffset);
                    
                    i = endOffset;
                }
            }
        }

        memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    printf("-----------------------------------------------------------------\n");
    
    if (regionMemory != NULL) {
        free(regionMemory);
    }

    printf("\nScan Complete!\n");
    printf("- Total Regions Scanned: %u\n", regionsScanned);
    printf("- Searchable Space Size: %llu MB\n", ((committedRegionsSize / 1024) / 1024));
    printf("- Total Matches Found: %u\n", matchesFound);

    CloseHandle(processHandle);

    return 0;
}