#ifndef CPABE_CORE_H
#define CPABE_CORE_H
#include "CPABE_types.h"
#include "CPABE_utils.h"
#include "CPABE_access.h"
int init_pairing(pairing_t &p, const char *filePath);
void aes256key_to_element(element_t &element, const unsigned char *key);
void element_to_aes256key(element_t &element, unsigned char *&key);
void init_CP_ABE_PK(CP_ABE_PK &pk, int nums);
void init_CP_ABE_SK(CP_ABE_SK &sk, int nums);
// void free_CP_ABE_PK(CP_ABE_PK *pk);
// void free_CP_ABE_SK(CP_ABE_SK *sk);

void cpabe_Setup(CP_ABE_PK &pk, CP_ABE_MSK &msk, pairing_t p);
void cpabe_Keygen(CP_ABE_SK &sk, int *auth, CP_ABE_PK &pk, CP_ABE_MSK &msk, pairing_t p);
void cpabe_Encrypt(int Access[], const unsigned char *key, CT &ct, CP_ABE_PK &pk, pairing_t pairing);
void cpabe_Decrypt(int Access[], pairing_t pairing, CT &ct, CP_ABE_SK &sk, unsigned char *&dec_key);

#endif