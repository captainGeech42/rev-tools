#include <Windows.h>
#include <stdio.h>

#define VERSION "1.0.1"

#define LOG(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__);
#define ERR(fmt, ...) printf("[!] " fmt "\n", ##__VA_ARGS__);

void *load_sc(const char *filepath) {
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ERR("failed to open file: %s", filepath);
        return NULL;
    }

    size_t shellcode_sz = GetFileSize(hFile, NULL);
    LOG("shellcode size: 0x%zx", shellcode_sz);

    void *mem = VirtualAlloc(NULL, shellcode_sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        ERR("failed to allocate memory");
        return NULL;
    }

    if (!ReadFile(hFile, mem, shellcode_sz, NULL, NULL)) {
        ERR("failed to read in shellcode");
        return NULL;
    }

    return mem;
}

void usage() {
    puts("scexec " VERSION " by @captainGeech42");
    puts("------");
    puts("usage: scexec [-o|--offset OFFSET] (filepath)");
    puts("    by default, payload will be executed from the beginning");
}

int main(int argc, const char *argv[]) {
    size_t start_offset = 0;
    const char *filepath = NULL;

    if (argc < 2) {
        usage();
        return 2;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--offset") == 0) {
            if (i+1<argc) {
                if (strncmp(argv[i+1], "0x", 2) == 0) {
                    if (sscanf(argv[i+1], "0x%zx", &start_offset) == 0) {
                        usage();
                        return 2;
                    }
                } else {
                    start_offset = atoi(argv[i+1]);
                    if (start_offset == 0 && strcmp(argv[i+1], "0") != 0) {
                        usage();
                        return 2;
                    }
                }
                i += 1;
            }
        } else {
            filepath = argv[i];
        }
    }

    if (!filepath) {
        usage();
        return 2;
    }

    LOG("loading shellcode from %s", filepath);
    void *sc_ptr = load_sc(filepath);

    if (!sc_ptr) {
        ERR("failed to load shellcode");
        return 1;
    }

    void *start_ptr = (unsigned char *)(sc_ptr)+start_offset;
    LOG("ready to execute shellcode at 0x%p (offset=0x%zx)", start_ptr, start_offset);
    LOG("press any key to continue...");
    getc(stdin);

    ((void (*)(void))(start_ptr))();

    return 0;
}