#ifndef CPABE_SERIALIZE_H
#define CPABE_SERIALIZE_H
#include "CPABE_types.h"
#include "CPABE_utils.h"
#include "CPABE_core.h"
#include "CPABE_access.h"
void serializeToFile(CP_ABE_MSK msk, const char *filename);
void deSerializeFromFile(CP_ABE_MSK &msk, const char *filename, pairing_t p);
void serializeToFile(CP_ABE_PK pk, const char *filename);
void deSerializeFromFile(CP_ABE_PK &pk, const char *filename, pairing_t p);
void serializeToFile(CP_ABE_SK sk, const char *filename);
void deSerializeFromFile(CP_ABE_SK &sk, const char *filename, pairing_t p);
void serializeToFile(CT ct, const char *filename);
void deSerializeFromFile(CT &ct, const char *filename, pairing_t p);
json cpabe_sk_to_json(CP_ABE_SK &sk);
CP_ABE_SK jsonToCPABESK(const json &sk_json, pairing_t p);
json ct_to_json(CT &ct);
CT jsonToCT(const json &ct_json, pairing_t p);
json cpabe_pk_to_json(CP_ABE_PK &pk);
CP_ABE_PK jsonToCPABEPK(const json &pk_json, pairing_t p);
// 内存序列化与反序列化（密文CT <-> 字节流）
int cpabe_SerializeCT(CT &ct, unsigned char *out_buf);
void cpabe_DeserializeCT(const unsigned char *in_buf, int in_len, CT &ct, pairing_t pairing);

#endif