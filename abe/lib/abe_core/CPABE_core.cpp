#include "CPABE_core.h"

int init_pairing(pairing_t &p, const char *filePath)
{
    char param[1024];

    FILE *f = fopen(filePath, "rb");
    if (f == NULL)
    {
        printf("///");
        return errno;
    }

    // read param file from param file
    size_t count = fread(param, 1, 1024, f);
    if (count == 0)
    {
        pbc_die("read init param error");
    }
    fclose(f);
    // initial a pairing
    pairing_init_set_buf(p, param, count);
    return 0;
}

void aes256key_to_element(element_t &element, const unsigned char *key)
{
    unsigned char *buff = new unsigned char[ELEMENT_SIZE];
    memset(buff, 0, ELEMENT_SIZE);
    memcpy(buff, key, 256 >> 3);
    element_from_bytes(element, buff);
    delete[] buff;
}

void element_to_aes256key(element_t &element, unsigned char *&key)
{
    int length = element_length_in_bytes(element);
    unsigned char *buff = new unsigned char[length];
    // key = new unsigned char[256>>3];
    memset(buff, 0, length);
    element_to_bytes(buff, element);
    memcpy(key, buff, 256 >> 3);
    delete[] buff;
}
// 初始化结构体，动态分配内存
void init_CP_ABE_PK(CP_ABE_PK &pk, int nums)
{
    pk.h = new element_t[nums]; // 动态分配内存
    pk.U = nums;
    if (pk.h == NULL)
    {
        printf("Memory allocation failed\n");
        exit(1); // 如果分配失败，退出程序
    }
}

void init_CP_ABE_SK(CP_ABE_SK &sk, int nums)
{
    sk.KX = new element_t[nums]; // 动态分配内存
    sk.U = nums;
    if (sk.KX == NULL)
    {
        printf("Memory allocation failed\n");
        exit(1);
    }
}
// // 释放内存
// void free_CP_ABE_PK(CP_ABE_PK *pk) {
//     free(pk->h);  // 释放内存
// }

// void free_CP_ABE_SK(CP_ABE_SK *sk) {
//     free(sk->KX);  // 释放内存
// }
void cpabe_Setup(CP_ABE_PK &pk, CP_ABE_MSK &msk, pairing_t p)
{
    // pairing_t p;
    // init_pairing(p,"a1.param");
    element_t alpha, a;
    element_init_Zr(alpha, p);
    element_random(alpha);

    element_init_Zr(a, p);
    element_random(a);

    element_init_G1(pk.g, p);
    element_random(pk.g);

    element_init_G1(pk.ga, p);
    element_pow_zn(pk.ga, pk.g, a);

    element_init_GT(pk.eggalpha, p);
    element_pairing(pk.eggalpha, pk.g, pk.g);
    element_pow_zn(pk.eggalpha, pk.eggalpha, alpha);

    for (int i = 0; i < pk.U; i++)
    {
        // pk.h[i] = new element_t;
        element_init_G1(pk.h[i], p);
        element_random(pk.h[i]);
    }
    element_init_G1(msk.galpha, p);
    element_pow_zn(msk.galpha, pk.g, alpha);

    element_clear(a);
    element_clear(alpha);
}
void cpabe_Keygen(CP_ABE_SK &sk, int *auth, CP_ABE_PK &pk, CP_ABE_MSK &msk, pairing_t p)
{
    // pairing_t p;
    // init_pairing(p,"a1.param");
    element_t t, gat;
    element_init_Zr(t, p);
    element_random(t);

    element_init_G1(gat, p);
    element_pow_zn(gat, pk.ga, t); // gat = g^at

    element_init_G1(sk.K, p);
    element_mul(sk.K, msk.galpha, gat); // K = g^alpha*g^at

    element_init_G1(sk.L, p);
    element_pow_zn(sk.L, pk.g, t); // L=g^t
    int nS = 0;
    int j = 0;
    for (int i = 0; i < sk.U; i++)
    {
        element_init_G1(sk.KX[i], p);
    }
    while (auth[nS] != 0)
    {
        j = auth[nS++] - 1;
        element_pow_zn(sk.KX[j], pk.h[j], t);
    }
    element_clear(t);
    element_clear(gat);

    // 存储属性数组到sk
    sk.auth_vec.clear();
    for (int i = 0; auth[i] != 0; ++i)
    {
        sk.auth_vec.push_back(auth[i]);
    }
    sk.auth_vec.push_back(0); // 结束标志
}
void cpabe_Encrypt(int Access[], const unsigned char *key, CT &ct, CP_ABE_PK &pk, pairing_t pairing)
{
    int m = find_m(Access);
    int d = find_d(Access);
    // int** LSSS = new int*[m];
    // for(int i=0;i<m;i++){
    // 	LSSS[i] = new int[d];
    // }
    element_t **LSSS = new element_t *[m];
    for (int i = 0; i < m; i++)
    {
        LSSS[i] = new element_t[d];
    };

    int *attr = new int[m];
    make_LSSS(Access, m, d, LSSS, attr, pairing);
    element_t *v = new element_t[d];
    element_t *lambda = new element_t[m];
    element_t *r = new element_t[m];

    for (int i = 0; i < d; i++)
    {
        element_init_Zr(v[i], pairing);
        element_random(v[i]);
    }

    element_t s;
    element_init_Zr(s, pairing);
    element_set(s, v[0]);

    element_t eggalphas;
    element_init_GT(eggalphas, pairing);
    // todo;
    element_t message;
    element_init_GT(message, pairing);
    aes256key_to_element(message, key);
    element_pow_zn(eggalphas, pk.eggalpha, s); // e(g,g)^alphas
    element_init_GT(ct.meggalphas, pairing);
    element_mul(ct.meggalphas, message, eggalphas);
    element_clear(eggalphas);
    element_clear(message);

    element_init_G1(ct.Cprime, pairing);
    element_pow_zn(ct.Cprime, pk.g, s); // Cprime = g^s

    for (int i = 0; i < m; i++)
    {
        element_init_Zr(r[i], pairing);
        element_random(r[i]);
    }

    element_t temp;
    element_init_Zr(temp, pairing);
    for (int i = 0; i < m; i++)
    {
        element_init_Zr(lambda[i], pairing);
        element_set0(lambda[i]);
        for (int j = 0; j < d; j++)
        {
            // element_set_si(temp,LSSS[i][j]);
            element_mul(temp, LSSS[i][j], v[j]);
            element_add(lambda[i], lambda[i], temp);
            // element_pow_zn(lambda[i],v[j],LSSS[i][j]);
        }
    }
    element_clear(temp);
    ct.C = new element_t[m];
    ct.D = new element_t[m];
    ct.m = m;
    element_t hr;
    element_init_G1(hr, pairing);
    // cout<<m<<endl;
    for (int i = 0; i < m; i++)
    {
        element_init_G1(ct.C[i], pairing);
        element_pow_zn(ct.C[i], pk.ga, lambda[i]);
        // cout<<char(attr[i])<<endl;
        element_pow_zn(hr, pk.h[attr[i] - 1], r[i]); // hr = h^r;
        element_invert(hr, hr);                        // hr = hr^-1
        element_mul(ct.C[i], ct.C[i], hr);
        element_init_G1(ct.D[i], pairing);
        element_pow_zn(ct.D[i], pk.g, r[i]); // D_i
    }
    element_clear(hr);
    delete[] attr;
    // for(int i=0;i<m;i++){
    // 	delete[] LSSS[i];
    // }
    // delete[] LSSS;
    for (int i = 0; i < m; i++)
    {
        for (int j = 0; j < d; j++)
        {
            element_clear(LSSS[i][j]); // 释放每个矩阵元素
        }
        delete[] LSSS[i]; // 释放每一行
    }
    delete[] LSSS;

    for (int i = 0; i < m; i++)
    {
        element_clear(lambda[i]);
        element_clear(r[i]);
    }
    for (int i = 0; i < d; i++)
    {
        element_clear(v[i]);
    }
    element_clear(s);
    // delete LSSS;
}
void cpabe_Decrypt(int Access[], pairing_t pairing, CT &ct, CP_ABE_SK &sk, unsigned char *&dec_key)
{
    // 使用 sk.auth_vec
    int m = find_m(Access);
    int d = find_d(Access);
    int old_d = d;
    int *rows = new int[m];
    element_t *w = new element_t[m];
    element_t **LSSS = new element_t *[m];
    for (int i = 0; i < m; i++)
    {
        LSSS[i] = new element_t[d + 1];
        for (int j = 0; j < d; j++)
        {
            element_init_Zr(LSSS[i][j], pairing);
        }
    }

    int *attr = new int[m];
    make_LSSS(Access, m, d, LSSS, attr, pairing);

    // 从 sk.auth_vec 构造 auth 数组
    int *auth = new int[sk.auth_vec.size()];
    for (size_t i = 0; i < sk.auth_vec.size(); ++i)
        auth[i] = sk.auth_vec[i];

    element_t order;
    element_init_Zr(order, pairing);
    element_set_mpz(order, pairing->r);

    bool det = reduce_LSSS(order, m, d, LSSS, attr, auth, rows, w, pairing);
    if (!det)
    {
        std::cout << "Unable to decrypt - insufficient attributes" << std::endl;
        exit(0);
    }

    if (m < d)
    {
        std::cout << "Unable to decrypt - insufficient attributes" << std::endl;
        exit(0);
    }

    element_t eck;
    element_init_GT(eck, pairing);
    element_pairing(eck, ct.Cprime, sk.K);

    element_t paie;
    element_init_GT(paie, pairing);
    element_set1(paie);

    element_t left;
    element_init_GT(left, pairing);
    element_t right;
    element_init_GT(right, pairing);

    element_t temp;
    element_init_GT(temp, pairing);

    element_t wi;
    element_init_Zr(wi, pairing);

    // Auth user attributes
    // Process each attribute (pho)
    for (int i = 0; i < m; i++)
    {
        element_pairing(left, ct.C[rows[i]], sk.L);
        element_pairing(right, sk.KX[attr[i] - 1], ct.D[rows[i]]);
        element_mul(temp, left, right);
        element_pow_zn(temp, temp, w[i]);
        element_mul(paie, paie, temp);
    }

    element_t result;
    element_init_GT(result, pairing);
    element_invert(paie, paie);
    element_mul(result, eck, paie);
    element_invert(result, result);
    element_mul(result, ct.meggalphas, result);
    element_to_aes256key(result, dec_key);

    // Clear temporary elements
    element_clear(eck);
    element_clear(left);
    element_clear(right);
    element_clear(wi);
    element_clear(temp);
    element_clear(paie);
    element_clear(result);
    element_clear(order);
    // Clean up dynamically allocated memory
    delete[] attr;
    delete[] auth;

    // Clean up the LSSS matrix
    for (int i = 0; i < m; i++)
    {
        for (int j = 0; j < old_d; j++)
        {
            // cout<<i<<" "<<j<<endl;
            element_clear(LSSS[i][j]); // Free each element
        }
        delete[] LSSS[i]; // Free each row
    }
    delete[] LSSS;

    // Clean up the w array
    for (int i = 0; i < m; i++)
    {
        element_clear(w[i]);
    }
    delete[] w;
}
