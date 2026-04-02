#ifndef CPABE_ACCESS_H
#define CPABE_ACCESS_H
#include "CPABE_types.h"
#include "CPABE_utils.h"
#include<set>
#include <sstream>
int numsOfAttributes(const int accessStructure[]);
void parseAccessString(const std::string &accessStr, int accessArray[]);
void make_LSSS(int Access[], int rows, int cols, element_t **LSSS, int *attr, pairing_t pairing);
bool gauss(element_t &order, int n, element_t **matrix, element_t *w, pairing_t pairing);
bool reduce_LSSS(
    element_t &order,
    int &m,
    int &d,
    element_t **LSSS,
    int *attr,
    int *auth,
    int *rows,
    element_t *w,
    pairing_t pairing);

#endif