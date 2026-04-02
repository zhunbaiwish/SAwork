#include "CPABE_utils.h"

int absval(int x)
{
    if (x < 0)
        return -x;
    return x;
}


ostream &operator<<(ostream &s, node &x)
{
    print_node(&x);
    return s;
}

// Find number of leaf attributes - the number of rows in Access matrix

int find_m(int Access[])
{
    int i, m;
    i = m = 0;
    while (Access[i] != 0)
    {
        i++;
        if (Access[i] < 0)
            m++;
    }
    return m;
}

// find number of columns in Access matrix = 1 + Sum of (thresholds-1) ??

int find_d(int Access[])
{
    int j, d, n;
    j = 0;
    d = 1;
    while (Access[j] > 0)
    {
        n = Access[j];
        if (n == 0)
            break;
        d += Access[j + 1] - 1;
        j += (n + 2);
    }
    return d;
}

// traverse Access tree and pretty-print it

void print_node(node *nd)
{
    int c, n = nd->n;
    if (n < 0)
    {
        cout << "(" << (char)(-n) << ")";
        return;
    }
    cout << "(";
    for (int i = 0; i < n; i++)
    {
        c = nd->child[i].n;
        if (c < 0)
            cout << (char)(-c) << ",";
        else
            print_node(&nd->child[i]);
    }
    cout << nd->t << "),";
}


int element_compare(element_t &a, element_t &b)
{
    mpz_t za, zb;
    mpz_init(za);
    mpz_init(zb);

    // 将 element_t 转换为 mpz_t
    element_to_mpz(za, a);
    element_to_mpz(zb, b);

    // 使用 GMP 的 mpz_cmp 比较大小
    int cmp_result = mpz_cmp(za, zb);

    mpz_clear(za);
    mpz_clear(zb);

    return cmp_result; // 返回比较结果
    // 返回值说明：
    // < 0 ： 如果 a < b
    //   0 ： 如果 a == b
    // > 0 ： 如果 a > b
}
int element_compare_to_zero(element_t &a)
{
    mpz_t za;
    mpz_init(za);

    // 将 element_t 转换为 GMP 的 mpz_t 类型
    element_to_mpz(za, a);

    // 使用 GMP 的 mpz_cmp_ui 比较 za 和 0
    int cmp_result = mpz_cmp_ui(za, 0);

    mpz_clear(za);

    return cmp_result;
    // 返回值说明：
    // < 0 ： 如果 a < 0
    //   0 ： 如果 a == 0
    // > 0 ： 如果 a > 0
}
void string_to_element(element_t &element, const string &str)
{
    int len = str.size();
    vector<unsigned char> buffer(ELEMENT_SIZE, 0);
    memcpy(buffer.data(), str.c_str(), len);
    element_from_bytes(element, buffer.data());
}
void element_to_string(element_t &element, string &str)
{
    int length = element_length_in_bytes(element);
    vector<unsigned char> buffer(length);
    element_to_bytes(buffer.data(), element);
    auto pos = std::find(buffer.begin(), buffer.end(), 0);
    str.assign(reinterpret_cast<char *>(buffer.data()), pos != buffer.end() ? pos - buffer.begin() : length);
}
// CP-ABE
std::string element_to_string(element_t &elem)
{
    char *str = new char[1024];       // 假设足够大，实际使用中可能需要根据情况调整
    element_snprint(str, 1024, elem); // 将 element_t 转换为字符串
    std::string result(str);
    delete[] str; // 释放分配的内存
    return result;
}