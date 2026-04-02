#ifndef CPABE_UTILS_H
#define CPABE_UTILS_H
#include "CPABE_types.h"

int absval(int x);


int find_m(int Access[]);
int find_d(int Access[]);
void print_node(node *nd);
std::ostream &operator<<(std::ostream &s, node &x);
int element_compare_to_zero(element_t &a);
int element_compare(element_t &a, element_t &b);
void string_to_element(element_t &element, const std::string &str);
void element_to_string(element_t &element, std::string &str);
std::string element_to_string(element_t &elem);

#endif