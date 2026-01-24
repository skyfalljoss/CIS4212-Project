#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


unsigned char* read_file( char filename[], int* length);
void write_hex_file(const char filename[], const unsigned char* data, int length);
unsigned char* generate_key(const unsigned char* seed, unsigned long message_length);
void xor_bytes(unsigned char* result, const unsigned char* a, const unsigned char* b, int length);
unsigned char* compute_sha256(const unsigned char* data, int length);

// -----------------Main Function-----------------
int main(int argc, char* argv[]) {

    // validate command arguments for alice it should be like ./alice Message.txt SharedSeed.txt
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <message_file> <seed_file>\n", argv[0]);
        return 1;
    }
    

    // 1: Read Message form Message.txt 
    int message_length;
    unsigned char* message = read_file(argv[1], &message_length);
    if (!message) return 1;
    
    // validate message length equal or greater than 32 bytes
    if (message_length < 32) {
        fprintf(stderr, "Message must be equal or greater than 32 bytes\n");
        free(message);
        return 1;
    }
    

    // 2: Read Seed from SharedSeed.txt
    int seed_length;
    unsigned char* seed = read_file(argv[2], &seed_length);
    if (!seed) {
        free(message);
        return 1;
    }
    
    // validate seed length equal to 32 bytes
    if (seed_length != 32) {
        fprintf(stderr, "Seed must be exactly 32 bytes\n");
        free(message);
        free(seed);
        return 1;
    }
    

    // 3: Generate Key using ChaCha20
    unsigned char* key = generate_key(seed, message_length);

    // 4: Write Key to Key.txt in hex format
    write_hex_file("Key.txt", key, message_length);
    
    // 5: Xor Message with Key to produce Ciphertext
    unsigned char* ciphertext = malloc(message_length);
    xor_bytes(ciphertext, message, key, message_length);
    // 6: Write Ciphertext to Ciphertext.txt in hex format
    write_hex_file("Ciphertext.txt", ciphertext, message_length);
    
    // Free allocated memory
    free(message);
    free(seed);
    free(key);
    free(ciphertext);
    
    //=================Acknowledgment Phase================== 
    //run after receiving Hash.txt from Bob 

    // 7 : Read Bob's Hash from Hash.txt
    int hash_length;
    unsigned char* bob_hash_hex = read_file("Hash.txt", &hash_length);
    
    // 8: Compute SHA-256 of original message and compare with Bob's hash
    if (bob_hash_hex) {
        // Re-read original message
        int original_length;
        unsigned char* original_message = read_file(argv[1], &original_length);
        if (!original_message) {
            free(bob_hash_hex);
            return 1;
        }
        // Compute SHA-256 of original message
        unsigned char* our_hash = compute_sha256(original_message, original_length);
        
        // Convert our_hash to hex string
        char our_hash_hex[65];
        for (int i = 0; i < 32; i++) {
            sprintf(our_hash_hex + i*2, "%02x", our_hash[i]);
        }
        our_hash_hex[64] = '\0';
        
        // Compare hashes
        int match = (hash_length >= 64 && memcmp(bob_hash_hex, our_hash_hex, 64) == 0);
        
        // Write acknowledgment to Acknowledgment.txt
        FILE* ack_file = fopen("Acknowledgment.txt", "w");
        if (ack_file) {
            fprintf(ack_file, "%s", match ? "Acknowledgment Successful" : "Acknowledgment Failed");
            fclose(ack_file);
        }
        
        free(bob_hash_hex);
        free(original_message);
    }
    
    return 0;
}

//=================Helper Functions==================

//---------------- Read from File -------------------
unsigned char* read_file( char fileName[], int* length) {
    FILE *pFile;
	pFile = fopen(fileName, "rb");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *length = temp_size-1;

    if (output == NULL)
    {
        printf("Memory allocation failed.\n");
        fclose(pFile);
        exit(0);
    }
	return output;
}


//---------------- Write to File -------------------
void write_hex_file(const char filename[], const unsigned char* data, int length) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        perror("Failed to create file");
        exit(1);
    }
    // convert to hex and write
    for (int i = 0; i < length; i++) {
        fprintf(file, "%02x", data[i]);
    }
    
    fclose(file);
}

//---------------- Generate PRNG Key -------------------
unsigned char* generate_key(const unsigned char* seed, unsigned long message_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    unsigned char nonce[16] = {0};
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce) != 1) {
        perror("Failed to initialize ChaCha20");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    
    unsigned char* key = malloc(message_length);
    unsigned char zeros[message_length];
    memset(zeros, 0, message_length);
    int out_len;
    
    if (EVP_EncryptUpdate(ctx, key, &out_len, zeros, message_length) != 1) {
        perror("Failed to generate key");
        free(key);
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    EVP_EncryptFinal_ex(ctx, key, &out_len);

    EVP_CIPHER_CTX_free(ctx);
    return key;
}

//---------------- XOR Bytes -------------------
void xor_bytes(unsigned char* result, const unsigned char* a, const unsigned char* b, int length) {
    for (int i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
}


//---------------- Compute SHA-256 -------------------
unsigned char* compute_sha256(const unsigned char* data, int length) {
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        perror("Failed to create hash context");
        exit(1);
    }
    unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, length) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        perror("Failed to compute hash");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    
    EVP_MD_CTX_free(ctx);
    return hash;
}
