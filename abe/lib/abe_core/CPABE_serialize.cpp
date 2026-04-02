#include "CPABE_serialize.h"

// 公钥结构体转json
json cpabe_pk_to_json(CP_ABE_PK &pk)
{
    json j;
    j["U"] = pk.U;
    j["g"] = element_to_string(pk.g);
    j["eggalpha"] = element_to_string(pk.eggalpha);
    j["ga"] = element_to_string(pk.ga);
    json jsonH = json::array();
    for (int i = 0; i < pk.U; i++)
    {
        jsonH.push_back(element_to_string(pk.h[i]));
    }
    j["h"] = jsonH;
    return j;
}

// json转公钥结构体
CP_ABE_PK jsonToCPABEPK(const json &pk_json, pairing_t p)
{
    CP_ABE_PK pk;
    pk.U = pk_json["U"].get<int>();
    init_CP_ABE_PK(pk, pk.U);

    // g
    element_init_G1(pk.g, p);
    element_set_str(pk.g, pk_json["g"].get<std::string>().c_str(), 10);

    // eggalpha
    element_init_GT(pk.eggalpha, p);
    element_set_str(pk.eggalpha, pk_json["eggalpha"].get<std::string>().c_str(), 10);

    // ga
    element_init_G1(pk.ga, p);
    element_set_str(pk.ga, pk_json["ga"].get<std::string>().c_str(), 10);

    // h[]
    for (int i = 0; i < pk.U; i++)
    {
        element_init_G1(pk.h[i], p);
        element_set_str(pk.h[i], pk_json["h"][i].get<std::string>().c_str(), 10);
    }
    return pk;
}

json cpabe_sk_to_json(CP_ABE_SK &sk)
{
    json j;
    j["U"] = sk.U;
    j["K"] = element_to_string(sk.K);
    j["L"] = element_to_string(sk.L);
    json jsonKX = json::array();
    for (int i = 0; i < sk.U; i++)
    {
        jsonKX.push_back(element_to_string(sk.KX[i]));
    }
    j["KX"] = jsonKX;
    // 新增：序列化属性数组
    j["auth_vec"] = sk.auth_vec;
    return j;
}
CP_ABE_SK jsonToCPABESK(const json &sk_json, pairing_t p)
{
    int U = sk_json["U"].get<int>();
    CP_ABE_SK sk;
    init_CP_ABE_SK(sk, U);
    sk.U = U;
    element_init_G1(sk.K, p);
    element_set_str(sk.K, sk_json["K"].get<std::string>().c_str(), 10);
    element_init_G1(sk.L, p);
    element_set_str(sk.L, sk_json["L"].get<std::string>().c_str(), 10);
    sk.KX = new element_t[sk.U];
    for (int i = 0; i < sk.U; i++)
    {
        element_init_G1(sk.KX[i], p);
        element_set_str(sk.KX[i], sk_json["KX"][i].get<std::string>().c_str(), 10);
    }
    sk.auth_vec = sk_json.at("auth_vec").get<std::vector<int>>();
    return sk;
}
// 将 CT 结构体转换为 JSON
json ct_to_json(CT &ct)
{
    json j;

    // 转换 meggalphas
    j["meggalphas"] = element_to_string(ct.meggalphas);

    // 转换 Cprime
    j["Cprime"] = element_to_string(ct.Cprime);

    // 转换 m
    j["m"] = ct.m;

    // 转换 C 数组
    json jsonC = json::array();
    for (int i = 0; i < ct.m; ++i)
    {
        jsonC.push_back(element_to_string(ct.C[i]));
    }
    j["C"] = jsonC;

    // 转换 D 数组
    json jsonD = json::array();
    for (int i = 0; i < ct.m; ++i)
    {
        jsonD.push_back(element_to_string(ct.D[i]));
    }
    j["D"] = jsonD;

    return j;
}

CT jsonToCT(const json &ct_json, pairing_t p)
{
    // pairing_t p;
    // init_pairing(p,"../keys/a.param");

    CT ct;
    // 读取 m
    ct.m = ct_json["m"].get<int>();

    // 需要将字符串转换为 element_t
    // meggalphas
    const std::string &meggalphas_value = ct_json["meggalphas"].get<std::string>();
    element_init_GT(ct.meggalphas, p);
    element_set_str(ct.meggalphas, meggalphas_value.c_str(), 10);
    // 读取 Cprime
    const std::string &cprime_value = ct_json["Cprime"].get<std::string>();
    element_init_G1(ct.Cprime, p);
    element_set_str(ct.Cprime, cprime_value.c_str(), 10);
    // 读取 C 数组
    ct.C = new element_t[ct.m];
    for (int i = 0; i < ct.m; ++i)
    {
        const std::string &c_value = ct_json["C"][i].get<std::string>();
        element_init_G1(ct.C[i], p);
        element_set_str(ct.C[i], c_value.c_str(), 10);
        // element_init(ct.C[i], ...); // 初始化 ct.C[i]
        // element_set_str(ct.C[i], c_value.c_str(), 10); // 适当的基数
    }

    ct.D = new element_t[ct.m];
    for (int i = 0; i < ct.m; ++i)
    {
        const std::string &d_value = ct_json["D"][i].get<std::string>();
        // element_init(ct.D[i], ...); // 初始化 ct.D[i]
        // element_set_str(ct.D[i], d_values[i].c_str(), 10); // 适当的基数
        element_init_G1(ct.D[i], p);
        element_set_str(ct.D[i], d_value.c_str(), 10);
    }

    return ct;
}
void serializeToFile(CP_ABE_MSK msk, const char *filename)
{
    FILE *outputFile = fopen(filename, "wb");
    if (outputFile == NULL)
    {
        printf("///");
        return;
    }
    element_out_str(outputFile, 10, msk.galpha);
    fputc('\n', outputFile);
    fclose(outputFile);
}
void deSerializeFromFile(CP_ABE_MSK &msk, const char *filename, pairing_t p)
{
    FILE *inputFile = fopen(filename, "rb");
    if (inputFile == NULL)
    {
        printf("///");
        return;
    }
    element_init_G1(msk.galpha, p);
    char galpha[1024];
    fgets(galpha, 1024, inputFile);
    // cout<<galpha;
    element_set_str(msk.galpha, galpha, 10);
    fclose(inputFile);
}
void serializeToFile(CP_ABE_PK pk, const char *filename)
{
    FILE *outputFile = fopen(filename, "wb");
    if (outputFile == NULL)
    {
        printf("///");
        return;
    }
    element_out_str(outputFile, 10, pk.eggalpha);
    fputc('\n', outputFile);
    element_out_str(outputFile, 10, pk.g);
    fputc('\n', outputFile);
    element_out_str(outputFile, 10, pk.ga);
    fputc('\n', outputFile);
    for (int i = 0; i < pk.U; i++)
    {
        element_out_str(outputFile, 10, pk.h[i]);
        fputc('\n', outputFile);
    }
    fclose(outputFile);
}
void deSerializeFromFile(CP_ABE_PK &pk, const char *filename, pairing_t p)
{
    FILE *inputFile = fopen(filename, "rb");
    if (inputFile == NULL)
    {
        printf("///");
        return;
    }
    char temp[1024];
    element_init_GT(pk.eggalpha, p);
    fgets(temp, 1024, inputFile);
    element_set_str(pk.eggalpha, temp, 10);

    memset(temp, 0, 1024);
    element_init_G1(pk.g, p);
    fgets(temp, 1024, inputFile);
    element_set_str(pk.g, temp, 10);

    memset(temp, 0, 1024);
    element_init_G1(pk.ga, p);
    fgets(temp, 1024, inputFile);
    element_set_str(pk.ga, temp, 10);

    for (int i = 0; i < pk.U; i++)
    {
        memset(temp, 0, 1024);
        element_init_G1(pk.h[i], p);
        fgets(temp, 1024, inputFile);
        element_set_str(pk.h[i], temp, 10);
    }

    fclose(inputFile);
}
void serializeToFile(CP_ABE_SK sk, const char *filename)
{
    FILE *outputFile = fopen(filename, "wb");
    if (outputFile == NULL)
    {
        printf("///");
        return;
    }
    element_out_str(outputFile, 10, sk.K);
    fputc('\n', outputFile);
    element_out_str(outputFile, 10, sk.L);
    fputc('\n', outputFile);
    for (int i = 0; i < sk.U; i++)
    {
        element_out_str(outputFile, 10, sk.KX[i]);
        fputc('\n', outputFile);
    }
    // 写入属性数组长度和内容
    int auth_len = sk.auth_vec.size();
    fprintf(outputFile, "%d\n", auth_len);
    for (int i = 0; i < auth_len; ++i)
    {
        fprintf(outputFile, "%d\n", sk.auth_vec[i]);
    }
    fclose(outputFile);
}
void deSerializeFromFile(CP_ABE_SK &sk, const char *filename, pairing_t p)
{
    FILE *inputFile = fopen(filename, "rb");
    if (inputFile == NULL)
    {
        printf("///");
        return;
    }
    char temp[1024];
    element_init_G1(sk.K, p);
    fgets(temp, 1024, inputFile);
    element_set_str(sk.K, temp, 10);

    memset(temp, 0, 1024);
    element_init_G1(sk.L, p);
    fgets(temp, 1024, inputFile);
    element_set_str(sk.L, temp, 10);

    for (int i = 0; i < sk.U; i++)
    {
        memset(temp, 0, 1024);
        element_init_G1(sk.KX[i], p);
        fgets(temp, 1024, inputFile);
        element_set_str(sk.KX[i], temp, 10);
    }
    // 读取属性数组长度和内容
    int auth_len = 0;
    fgets(temp, 1024, inputFile);
    sscanf(temp, "%d", &auth_len);
    sk.auth_vec.clear();
    for (int i = 0; i < auth_len; ++i)
    {
        memset(temp, 0, 1024);
        fgets(temp, 1024, inputFile);
        int val = 0;
        sscanf(temp, "%d", &val);
        sk.auth_vec.push_back(val);
    }
    fclose(inputFile);
}
void serializeToFile(CT ct, const char *filename)
{
    FILE *outputFile = fopen(filename, "wb");
    if (outputFile == NULL)
    {
        printf("///");
        return;
    }
    element_out_str(outputFile, 10, ct.meggalphas);
    fputc('\n', outputFile);
    element_out_str(outputFile, 10, ct.Cprime);
    fputc('\n', outputFile);

    fprintf(outputFile, "%d", ct.m);
    fputc('\n', outputFile);

    for (int i = 0; i < ct.m; i++)
    {
        element_out_str(outputFile, 10, ct.C[i]);
        fputc('\n', outputFile);
        element_out_str(outputFile, 10, ct.D[i]);
        fputc('\n', outputFile);
    }
    fclose(outputFile);
}
void deSerializeFromFile(CT &ct, const char *filename, pairing_t p)
{
    FILE *inputFile = fopen(filename, "rb");
    if (inputFile == NULL)
    {
        printf("///");
        return;
    }
    char temp[1024];
    element_init_GT(ct.meggalphas, p);
    fgets(temp, 1024, inputFile);
    element_set_str(ct.meggalphas, temp, 10);

    memset(temp, 0, 1024);
    element_init_G1(ct.Cprime, p);
    fgets(temp, 1024, inputFile);
    element_set_str(ct.Cprime, temp, 10);

    memset(temp, 0, 1024);
    fgets(temp, 1024, inputFile);
    ct.m = atoi(temp);
    ct.C = new element_t[ct.m];
    ct.D = new element_t[ct.m];
    for (int i = 0; i < ct.m; i++)
    {
        memset(temp, 0, 1024);
        element_init_G1(ct.C[i], p);
        fgets(temp, 1024, inputFile);
        element_set_str(ct.C[i], temp, 10);

        memset(temp, 0, 1024);
        element_init_G1(ct.D[i], p);
        fgets(temp, 1024, inputFile);
        element_set_str(ct.D[i], temp, 10);
    }

    fclose(inputFile);
}
// CT结构体的内存序列化与反序列化
int cpabe_SerializeCT(CT &ct, unsigned char *out_buf) {
    int offset = 0;
    int len;

    // 1. 序列化 meggalphas (GT)
    len = element_length_in_bytes(ct.meggalphas);
    memcpy(out_buf + offset, &len, sizeof(int));
    offset += sizeof(int);
    element_to_bytes(out_buf + offset, ct.meggalphas);
    offset += len;

    // 2. 序列化 Cprime (G1)
    len = element_length_in_bytes(ct.Cprime);
    memcpy(out_buf + offset, &len, sizeof(int));
    offset += sizeof(int);
    element_to_bytes(out_buf + offset, ct.Cprime);
    offset += len;

    // 3. 序列化 m
    memcpy(out_buf + offset, &ct.m, sizeof(int));
    offset += sizeof(int);

    // 4. 序列化 C[i] (G1)
    for (int i = 0; i < ct.m; ++i) {
        len = element_length_in_bytes(ct.C[i]);
        memcpy(out_buf + offset, &len, sizeof(int));
        offset += sizeof(int);
        element_to_bytes(out_buf + offset, ct.C[i]);
        offset += len;
    }

    // 5. 序列化 D[i] (G1)
    for (int i = 0; i < ct.m; ++i) {
        len = element_length_in_bytes(ct.D[i]);
        memcpy(out_buf + offset, &len, sizeof(int));
        offset += sizeof(int);
        element_to_bytes(out_buf + offset, ct.D[i]);
        offset += len;
    }

    return offset; // 返回总长度
}

void cpabe_DeserializeCT(const unsigned char *in_buf, int in_len, CT &ct, pairing_t pairing) {
    int offset = 0;
    int len;

    // 1. 反序列化 meggalphas (GT)
    memcpy(&len, in_buf + offset, sizeof(int));
    offset += sizeof(int);
    element_init_GT(ct.meggalphas, pairing);
    element_from_bytes(ct.meggalphas, (unsigned char*)(in_buf + offset));
    offset += len;

    // 2. 反序列化 Cprime (G1)
    memcpy(&len, in_buf + offset, sizeof(int));
    offset += sizeof(int);
    element_init_G1(ct.Cprime, pairing);
    element_from_bytes(ct.Cprime, (unsigned char*)(in_buf + offset));
    offset += len;

    // 3. 反序列化 m
    memcpy(&ct.m, in_buf + offset, sizeof(int));
    offset += sizeof(int);

    // 4. 反序列化 C[i] (G1)
    ct.C = new element_t[ct.m];
    for (int i = 0; i < ct.m; ++i) {
        memcpy(&len, in_buf + offset, sizeof(int));
        offset += sizeof(int);
        element_init_G1(ct.C[i], pairing);
        element_from_bytes(ct.C[i], (unsigned char*)(in_buf + offset));
        offset += len;
    }

    // 5. 反序列化 D[i] (G1)
    ct.D = new element_t[ct.m];
    for (int i = 0; i < ct.m; ++i) {
        memcpy(&len, in_buf + offset, sizeof(int));
        offset += sizeof(int);
        element_init_G1(ct.D[i], pairing);
        element_from_bytes(ct.D[i], (unsigned char*)(in_buf + offset));
        offset += len;
    }
}
