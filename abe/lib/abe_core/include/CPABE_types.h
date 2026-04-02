#ifndef CPABE_TYPES_H
#define CPABE_TYPES_H
#include <pbc/pbc.h>
#include <string>
#include <iostream>
#include <vector>
#include "./json.hpp"
using namespace std;
using json = nlohmann::json;
const int MAX_ACCESS_SIZE = 1000;
const int ELEMENT_SIZE  = 128; // 每个 element_t 的大小
class node
{
public:
    int n;
    int t;
    node *child;
    node()
    {
        n = t = 0;
        child = NULL;
    }
    node &operator=(node &);
    node(int *); // construct from access structure
    friend std::ostream &operator<<(std::ostream &, node &);
    ~node();
};
void fill_node(node *nd, int *Access, int ipos);
void delete_node(node *nd);
void copy_node(node *f, node *t);
int find_index(int Access[], int i);
typedef struct _CP_ABE_PK
{
    element_t g;
    element_t eggalpha;
    element_t ga;
    element_t *h;
    int U;
} CP_ABE_PK;

typedef struct _CP_ABE_MSK
{
    element_t galpha;
} CP_ABE_MSK;

typedef struct _CP_ABE_SK
{
    element_t K;
    element_t L;
    element_t *KX;
    int U;
    std::vector<int> auth_vec; // 存储属性数组
    // 或 int* auth; int auth_len;
} CP_ABE_SK;

typedef struct _CT
{
    element_t meggalphas;
    element_t Cprime;
    int m;
    element_t *C;
    element_t *D;
} CT;

#endif