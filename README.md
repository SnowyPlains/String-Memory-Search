# Target Process Memory String Searcher
#### Description: A native Windows memory forensics utility written in pure C that inspects the virtual address space of a target running process to locate specific ASCII strings or byte signatures. Built using low-level Win32 APIs (VirtualQueryEx, ReadProcessMemory, OpenProcess, IsWow64Process2), this tool bridges static binary analysis with live process introspection, safely bypassing null-terminator limitations to scan raw binary memory regions.
#### Date: 13 October 2026

## Features:
- **Robust Argument Parsing:** Validates target Process IDs using strtol, checking for malformed inputs, string overflows (ERANGE), negative numbers, and empty search strings.
- **Dual-Architecture Target Support:** Automatically detects whether a target application runs as a 32-bit or native 64-bit process using IsWow64Process2.
- **Virtual Address Space Traversal:** Iterates through the entire user-mode address boundary (up to 0x7FFFFFFF for 32-bit or 0x00007FFFFFFFFFFF for 64-bit) via VirtualQueryEx.
- **Intelligent Region Filtering:** Automatically isolates committed memory pages with read permissions while explicitly skipping thread stack guard pages.
- **Cross-Process Memory Reading:** Dynamically allocates and scales local heap buffers using malloc and realloc to mirror and read remote process blocks safely via ReadProcessMemory.
- **Safe Bounded Binary Scanning:** Replaces standard null-terminated string functions with memcmp-based byte-sequence scanning over raw binary buffers to handle embedded null bytes correctly.
- **Contextual String Extraction:** Implements forward and backward boundary scanning using isprint() to automatically expand and display the full surrounding readable text string for every matched occurrence.

## Compilation & Usage:
**Prerequisites:**  
Any C standard compliant compiler such as gcc, clang, ...

**Build Instructions Example Using GCC:**
gcc -Wall -Wextra -O3 main.c -o StringSearch

*StringSearch is the name of the program, you can name it anything you want

**Execution Examples:**  
- **General Syntax:** .\StringSearch.exe \<pid\> "String_to_Search"
- **Example:** .\StringSearch.exe 2687 "Secret String"

## Sample Output:
```
==========================================================================================
                                  Memory String Searcher                                  
==========================================================================================

Target PID: 26800
String to Search: API_KEY
Target Process Architecture: 64-bit
--------------------------------------------

Scanning Memory Regions..
    Match #1
    - Match Found at Address: 0x140701391040649
    - Full String Address: 0x00007ff7986eb089
    - Full String: API_KEY = Hello Everyone!

    Match #2
    - Match Found at Address: 0x140701391040697
    - Full String Address: 0x00007ff7986eb0b9
    - Full String: API_KEY2 = Secret API
-----------------------------------------------------------------

Scan Complete!
- Total Regions Scanned: 64
- Searchable Space Size: 9 MB
- Total Matches Found: 2
```

## Engineering Journal and Implementation Process:
This section documents a summary of the implementation process:

### Phase 1: Argument Parsing and Robust PID Validation
First, I made sure that the amount of arguments was correct. If argc < 3 or argc > 3, the program exits with an error message displaying proper usage.

Next, I validated the PID argument using strtol. I checked if:
- endPtr == argv[1]. Testing if the provided input was a pure string
- *endPtr != '\0'. Checking for trailing characters after the number
- errno == ERANGE. Checking for numerical overflow
- pid < 0. Ensuring the PID isn't negative

Finally, I verified that the search string provided in argv[2] wasn't empty.

### Phase 2: Handle Acquisition & Upgrading Access Rights
Much of the initialization logic shared patterns with Project 5, but with a vital modification. To read memory from a foreign process, OpenProcess requires PROCESS_VM_READ rights in addition to PROCESS_QUERY_INFORMATION:
```c
HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
if (processHandle == NULL) {
    printf("Couldn't get a Handle to the Process! Error Code: %lu\n", GetLastError());
    return -1;
}
```

### Phase 3: Determining Target Architecture with IsWow64Process2
Just like in Project 5, I defined _WIN32_WINNT to 0x0A00 (Windows 10) and used IsWow64Process2 to determine whether the target process was running under a 32-bit emulator or natively as 64-bit, falling back to nativeMachine when processMachine returned IMAGE_FILE_MACHINE_UNKNOWN.

### Phase 4: Virtual Address Space Traversal & Filtering
I set up the traversal loop using VirtualQueryEx, defining user-space memory limits (0x7FFFFFFF for 32-bit and 0x00007FFFFFFFFFFF for 64-bit). Inside the loop, I filtered out unwanted regions:
- Skipped blocks where mbi.State != MEM_COMMIT.
- Skipped thread stack guard pages (mbi.Protect & PAGE_GUARD).
- Skipped regions lacking read permissions, while explicitly permitting PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY, and PAGE_EXECUTE_WRITECOPY.

### Phase 5: Dynamic Buffer Allocation & ReadProcessMemory Integration
To hold remote region data locally, I allocated a heap buffer using malloc, allowing it to scale dynamically across varying region sizes using realloc.

After confirming successful memory allocation, I called ReadProcessMemory:
```c
if ((ReadProcessMemory(processHandle, mbi.BaseAddress, regionMemory, mbi.RegionSize, &bytesRead)) == 0) {
    printf("Couldn't read Memory! Skipping the region!\n");
    memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    continue;
}
```
And made sure to release the buffer with free() after completing the scan.

### Phase 6: Overcoming the strstr() Trap with memcmp
At first, I tried using `strstr(regionMemory, argv[2])`. However, searching for my test strings failed, while searching for single characters returned junk. I realized that strstr() relies on null terminators (\0), which fail instantly when scanning raw binary memory blobs packed with null bytes.

To fix this, I replaced it with a size-bounded scan using memcmp over the exact number of bytes read (bytesRead):
```c
size_t stringToSearchLength = strlen(argv[2]);
if (bytesRead >= stringToSearchLength) {
    for (size_t i = 0; i <= (bytesRead - stringToSearchLength); i++) {
        if (memcmp((char*)regionMemory + i, argv[2], stringToSearchLength) == 0) {
            uintptr_t stringFoundAddress = (uintptr_t)mbi.BaseAddress + i;
            // ...
        }
    }
}
```

### Phase 7: Advanced Contextual String Expansion
To make the tool output more useful results, I wanted it to display the entire readable string surrounding a match rather than just the matching snippet. I implemented forward and backward scanning loops using isprint():
- Backward Scan: Decrements from the match start index while characters are printable and non-null.
- Forward Scan: Increments past the search term length while characters are printable and non-null.

This allowed the tool to output clean, fully reconstructed strings along with their precise remote virtual addresses.