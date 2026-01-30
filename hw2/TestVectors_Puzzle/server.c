#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/*
    File I/O Functions
*/

 // Read File
 char* Read_File(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    
    // Remove trailing whitespace
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
                              buffer[read_size-1] == '\r' || 
                              buffer[read_size-1] == ' ')) {
        buffer[--read_size] = '\0';
    }
    
    *length = read_size;
    fclose(file);
    return buffer;
}

 // Write string to file
int Write_File(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}

/*
    Hex Conversion Functions
*/

 // Convert hex string to byte array
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len) {
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }
    
    int byte_len = hex_len / 2;
    for (int i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }
    
    return byte_len;
}

 // Convert byte array to hex string
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}

/*
    Cryptographic Functions
*/

// SHA256 hash
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);

    return 0;
}

/*
    Utility Functions
*/

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}

int Write_Int_To_File(const char *filename, int value) {
    char buffer[32];
    sprintf(buffer, "%d", value);
    return Write_File(filename, buffer);
}

void Print_Hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


// Server
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <ChallengeFile> <DifficultyFile>\n", argv[0]);
        return 1;
    }

    const char *challenge_file = argv[1];
    const char *difficulty_file = argv[2];

    // 1. Read the challenge data from the input file (Challenge.txt)
    int challenge_len = 0;
    char *challenge_hex = Read_File(challenge_file, &challenge_len);
    if (!challenge_hex) {
        fprintf(stderr, "Error reading challenge file.\n");
        return 1;
    }

    // 2. Read the difficulty level from the input file (Difficulty.txt)
    int k = Read_Int_From_File(difficulty_file);
    if (k < 0) {
        fprintf(stderr, "Error reading difficulty file.\n");
        free(challenge_hex);
        return 1;
    }

    // 3. Server writes the challenge to "puzzle_challenge.txt"
    if (Write_File("puzzle_challenge.txt", challenge_hex) != 0) {
        fprintf(stderr, "Error writing puzzle_challenge.txt\n");
        free(challenge_hex);
        return 1;
    }

    // 4. Server writes the difficulty k to "puzzle_k.txt"
    if (Write_Int_To_File("puzzle_k.txt", k) != 0) {
        fprintf(stderr, "Error writing puzzle_k.txt\n");
        free(challenge_hex);
        return 1;
    }

    printf("Server: Puzzle generated. k=%d\n", k);

    free(challenge_hex);
    return 0;
}
