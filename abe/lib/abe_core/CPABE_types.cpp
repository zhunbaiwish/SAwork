#include "CPABE_types.h"

// get node index for i-th node

int find_index(int Access[], int i)
{
    int n, j, k;
    j = k = 0;
    while (k < i)
    {
        n = Access[j];
        if (n == 0)
            return -1;
        j += (n + 2);
        k++;
    }
    return j;
}
// fill tree data structure from data

void fill_node(node *nd, int *Access, int ipos)
{
    int i, j, k;
    nd->n = Access[ipos];

    nd->t = Access[ipos + 1];

    nd->child = new node[nd->n];
    for (i = 0; i < nd->n; i++)
    {
        k = Access[ipos + 2 + i];
        if (k < 0)
            nd->child[i].n = k;
        else
        {
            j = find_index(Access, k);
            fill_node(&nd->child[i], Access, j);
        }
    }
}

void delete_node(node *nd)
{
    int i, n = nd->n;
    nd->n = 0;
    nd->t = 0;
    if (n <= 0)
        return;
    for (i = 0; i < n; i++)
        delete_node(&nd->child[i]);
    delete[] nd->child;
    nd->child = NULL;
}

void copy_node(node *f, node *t)
{
    int i;
    t->n = f->n;
    if (t->n <= 0)
        return;
    t->t = f->t;
    t->child = new node[t->n];
    for (i = 0; i < t->n; i++)
        copy_node(&f->child[i], &t->child[i]);
}
// node constructor

node::node(int *Access)
{
    fill_node(this, Access, 0);
}

// node destructor

node::~node()
{
    delete_node(this);
}

node &node::operator=(node &b)
{
    delete_node(this);
    copy_node(&b, this);
    return *this;
}


// node 构造、析构、赋值等实现
// ... node::node, node::~node, node::operator=, fill_node, delete_node, copy_node, print_node, operator<< ...