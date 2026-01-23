#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

unsigned char *Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int inputLen);
void Convert_to_Hex(char output[], unsigned char input[], int inputLen);
void Show_in_Hex(char name[], unsigned char hex[], int hexLen);
unsigned char *Convert_from_Hex(const char *hex_string, int *out_len);
unsigned char *PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char *Hash_SHA256(unsigned char *input, unsigned long inputlen);

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Wrong number of arguments. Use %s <input_file>\n", argv[0]);
        return 1;
    }

    char *inputFile = argv[1];
    int seedLen;
    unsigned char *seed = Read_File(inputFile, &seedLen); // key is 32 bytes

    Show_in_Hex("Seed", seed, seedLen);

    inputFile = "Ciphertext.txt";
    int hexLen;
    unsigned char *ciphertextHex = Read_File(inputFile, &hexLen);

    Show_in_Hex("Ciphertext (Hex)", ciphertextHex, hexLen);

    int msgLen;
    unsigned char *ciphertext = Convert_from_Hex((char *)ciphertextHex, &msgLen);
    free(ciphertextHex);

    Show_in_Hex("Ciphertext", ciphertext, msgLen);

    unsigned char *secretKey = PRNG(seed, seedLen, msgLen);

    unsigned char *plaintext = malloc(msgLen);

    for (int i = 0; i < msgLen; i++)
    {
        plaintext[i] = ciphertext[i] ^ secretKey[i];
    }

    Show_in_Hex("Plaintext", plaintext, msgLen);

    char *outputFile = "Plaintext.txt";
    Write_File(outputFile, (char *)plaintext, msgLen);

    outputFile = "Hash.txt";
    unsigned char *hash = Hash_SHA256(plaintext, msgLen);
    char hashHex[SHA256_DIGEST_LENGTH * 2 + 1];
    Convert_to_Hex(hashHex, hash, SHA256_DIGEST_LENGTH);
    Write_File(outputFile, hashHex, SHA256_DIGEST_LENGTH * 2);
    return 0;
}

/*************************************************************
F u n c t i o n s
**************************************************************/
/*============================
Read from File
==============================*/
unsigned char *Read_File(char fileName[], int *fileLen)
{
    FILE *pFile;
    pFile = fopen(fileName, "r");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile) + 1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char *)malloc(temp_size);
    fgets(output, temp_size, pFile);
    fclose(pFile);
    *fileLen = temp_size - 1;
    return output;
}
/*============================
Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length)
{
    FILE *pFile;
    pFile = fopen(fileName, "w");
    if (pFile == NULL)
    {
        printf("Error opening file. \n");
        exit(0);
    }
    // fputs(input, pFile);
    fwrite(input, 1, input_length, pFile);
    fclose(pFile);
}
/*============================
Showing in Hex
==============================*/
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
    printf("%s: ", name);
    for (int i = 0; i < hexlen; i++)
        printf("%02x", hex[i]);
    printf("\n");
}
/*============================
Convert to Hex
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i = 0; i < inputlength; i++)
    {
        sprintf(&output[2 * i], "%02x", input[i]);
    }
    printf("Hex format: %s\n", output); // remove later
}
/*============================
PRNG Fucntion
==============================*/
unsigned char *PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pseudoRandomNumber = malloc(prnglen);
    unsigned char nonce[16] = {0};
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);
    unsigned char zeros[prnglen];
    memset(zeros, 0, prnglen);
    int outlen;
    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    EVP_EncryptFinal(ctx, pseudoRandomNumber, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return pseudoRandomNumber;
}
/*============================
SHA-256 Fucntion
==============================*/
unsigned char *Hash_SHA256(unsigned char *input, unsigned long inputlen)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    return hash;
}

unsigned char *Convert_from_Hex(const char *hex_string, int *out_len)
{
    int len = strlen(hex_string);
    if (len % 2 != 0)
    {
        fprintf(stderr, "Invalid hex string length\n");
        return NULL;
    }

    *out_len = len / 2;
    unsigned char *bytes = malloc(*out_len);

    for (int i = 0; i < *out_len; i++)
    {
        sscanf(hex_string + 2 * i, "%2hhx", &bytes[i]);
    }

    return bytes;
}
