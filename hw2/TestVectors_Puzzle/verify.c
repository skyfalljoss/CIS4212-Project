/**
    Useful Functions for Client-Server Puzzle and Merkle Hash Tree (MHT) Assignments

    This file provides utility functions for reading and writing hex strings),hex conversions,
    SHA256 operations

    Students can use these functions directly or modify them as needed
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/*
    File I/O Functions
*/

// Read File
char *Read_File(const char *filename, int *length)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char *)malloc(file_size + 1);
    if (!buffer)
    {
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';

    // Remove trailing whitespace
    while (read_size > 0 && (buffer[read_size - 1] == '\n' ||
                             buffer[read_size - 1] == '\r' ||
                             buffer[read_size - 1] == ' '))
    {
        buffer[--read_size] = '\0';
    }

    *length = read_size;
    fclose(file);
    return buffer;
}

// Write string to file
int Write_File(const char *filename, const char *data)
{
    FILE *file = fopen(filename, "w");
    if (!file)
    {
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
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len)
{
    if (hex_len % 2 != 0)
    {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }

    int challenge_len = hex_len / 2;
    for (int i = 0; i < challenge_len; i++)
    {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1)
        {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }

    return challenge_len;
}

// Convert byte array to hex string
int Bytes_to_Hex(const unsigned char *bytes, int challenge_len, char *hex)
{
    for (int i = 0; i < challenge_len; i++)
    {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[challenge_len * 2] = '\0';
    return challenge_len * 2;
}

/*
    Cryptographic Functions
*/

// SHA256 hash
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output)
{

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

int Read_Int_From_File(const char *filename)
{
    int length;
    char *str = Read_File(filename, &length);
    if (!str)
        return -1;

    int value = atoi(str);
    free(str);
    return value;
}

int Write_Int_To_File(const char *filename, int value)
{
    char buffer[32];
    sprintf(buffer, "%d", value);
    return Write_File(filename, buffer);
}

void Print_Hex(const char *label, const unsigned char *data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Insufficient Arguments!");
        return 1;
    }
    char *challenge_file = argv[1];
    char *difficulty_file = argv[2];
    char *nonce_file = argv[3];
    int challenge_hex_len;

    // Read challenge and convert to bytes
    char *challenge_hex = Read_File(challenge_file, &challenge_hex_len);
    unsigned char *challenge = malloc(challenge_hex_len / 2);
    int challenge_len = Hex_to_Bytes(challenge_hex, challenge, challenge_hex_len);

    // Read difficulty
    int k = Read_Int_From_File(difficulty_file);

    // Read nonce
    int nonce_hex_len;
    char *nonce_hex = Read_File(nonce_file, &nonce_hex_len);
    unsigned char *nonce = malloc(nonce_hex_len / 2);
    int nonce_len = Hex_to_Bytes(nonce_hex, nonce, nonce_hex_len);

    // Brute-force puzzle solution
    bool valid = true;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char data[challenge_len + nonce_len];
    memcpy(data, challenge, challenge_len);
    memcpy(data + challenge_len, nonce, nonce_len);
    Compute_SHA256(data, challenge_len + nonce_len, hash);

    // A valid solution is when hash has k leading 0 bits
    for (int i = 0; i < k; ++i)
    {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        if ((hash[byte_idx] >> bit_idx) & 1)
        {
            valid = false;
            break;
        }
    }

    if (valid)
        Write_File("verification_result.txt", "ACCEPT");
    else
        Write_File("verification_result.txt", "REJECT");

    return 0;
}