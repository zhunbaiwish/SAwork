#include "CPABE_access.h"
// 将字符串转换为 Access 控制结构数组
void parseAccessString(const std::string &accessStr, int accessArray[])
{
    std::istringstream stream(accessStr);
    std::string token;
    int index = 0;
    while (std::getline(stream, token, ','))
    {
        if (token[0] == '-')
        {
            accessArray[index++] = -(token[1]-'0'); // 将数字转换为负值
        }
        else
        {
            accessArray[index++] = std::stoi(token); // 转换为整数
        }
    }
    accessArray[index++] = 0; // 结束符
}
int numsOfAttributes(const int accessStructure[])
{
    std::set<char> uniqueAttributes; // 用于存储不同的字母属性
    // 遍历访问结构数组
    int i = 0;
    while (accessStructure[i] != 0)
    {
        if (accessStructure[i] < 0)
        {
            uniqueAttributes.insert(static_cast<char>(-accessStructure[i]));
        }
        i++;
    }
    // 返回去重后的字母属性个数
    return uniqueAttributes.size();
}

//
// make LSSS matrix of size rowsXcols from Access description
// attr[i] contains attribute of each row.
// algorithm due to Liu and Cao http://eprint.iacr.org/2010/374
// (but much simplified)
//
void make_LSSS(int Access[], int rows, int cols, element_t **LSSS, int *attr, pairing_t pairing)
{
    int i, j, z, m, d, n, t;
    element_t k;              // 用于存储系数的 PBC 元素
    node Fz, root(Access);    // 假设你有 node 类型及其实现
    node *L = new node[rows]; // 存储节点信息

    // 初始化 LSSS 矩阵
    for (i = 0; i < rows; i++)
    {
        for (j = 0; j < cols; j++)
        {
            element_init_Zr(LSSS[i][j], pairing); // 初始化每个矩阵元素
            element_set_si(LSSS[i][j], 0);        // 设置为 0
        }
    }

    // 初始化根节点的值
    element_set_si(LSSS[0][0], 1); // 设置 LSSS[0][0] 为 1
    L[0] = root;                   // 根节点
    m = 1;                         // 当前行数
    d = 1;                         // 当前列数

    // 初始化 k
    element_init_Zr(k, pairing);

    // 主循环
    for (;;)
    {
        z = -1;
        for (i = 0; i < m; i++)
        {
            if (L[i].n < 0)
                continue;
            z = i;
            break;
        }
        if (z < 0)
            break;

        Fz = L[z]; // 当前节点
        n = Fz.n;  // 子节点数
        t = Fz.t;  // 阈值

        // 节点数组右移
        for (i = m - 1; i >= z; i--)
        {
            L[i + n - 1] = L[i];
        }

        // 填充子节点
        for (i = 0; i < n; i++)
        {
            L[z + i] = Fz.child[i];
        }

        // 矩阵扩展
        for (i = m - 1; i >= z; i--)
        {
            for (j = 0; j < d; j++)
            {
                element_set(LSSS[i + n - 1][j], LSSS[i][j]); // 复制旧值
            }
        }

        // 生成新矩阵行
        for (i = 0; i < n; i++)
        {
            element_set_si(k, 1); // k = 1
            for (j = 0; j < d; j++)
            {
                element_set(LSSS[z + i][j], LSSS[z][j]); // 复制原值
            }
            for (j = 1; j < t; j++)
            {
                element_mul_si(k, k, (i + 1));          // k *= (i + 1)
                element_set(LSSS[z + i][d + j - 1], k); // 设置新的列值
            }
        }

        m = m + n - 1; // 更新行数
        d = d + t - 1; // 更新列数
    }

    // 填充属性数组
    for (i = 0; i < m; i++)
    {
        attr[i] = -L[i].n; // 叶子节点的负值作为属性
    }

    // 释放内存
    delete[] L;
    element_clear(k); // 释放临时变量 k
}
bool gauss(element_t &order, int n, element_t **matrix, element_t *w, pairing_t pairing)
{
    int i, ii, j, jj, k, m;
    int *row;
    bool ok, pivot;
    element_t s, p, half_order, two;

    // 初始化
    ok = true;

    element_init_Zr(s, pairing); // 用于存储计算中的临时变量
    element_init_Zr(p, pairing); // 用于存储逆元
    element_init_Zr(half_order, pairing);
    element_init_Zr(two, pairing);
    element_set_si(two, 2);
    element_div(half_order, order, two); // half_order = order / 2

    row = new int[n];
    for (i = 0; i < n; i++)
    {
        element_init_Zr(w[i], pairing);
        if (i == 0)
            element_set_si(w[i], 1); // w[0] = 1
        else
            element_set_si(w[i], 0); // w[i] = 0
        row[i] = i;                  // 初始化行索引
    }

    for (i = 0; i < n; i++)
    {
        element_init_Zr(matrix[i][n], pairing); // 初始化扩展列
        element_set(matrix[i][n], w[i]);        // matrix[i][n] = w[i]
    }

    for (i = 0; i < n; i++)
    {
        /* Gaussian elimination */
        m = i;
        ii = row[i];
        pivot = true;

        if (element_is0(matrix[ii][i]))
        {
            /* 找非零的主元 */
            pivot = false;
            for (j = i + 1; j < n; j++)
            {
                jj = row[j];
                if (!element_is0(matrix[jj][i]))
                {
                    m = j;
                    pivot = true;

                    // 交换行索引
                    k = row[i];
                    row[i] = row[m];
                    row[m] = k;
                    break;
                }
            }
        }

        if (!pivot)
        {
            ok = false; // 无法找到非零主元
            break;
        }

        ii = row[i];
        element_invert(p, matrix[ii][i]); // 计算主元的逆元 p = 1 / matrix[ii][i]

        for (j = i + 1; j < n; j++)
        {
            jj = row[j];
            element_mul(s, matrix[jj][i], p); // s = matrix[jj][i] * p

            for (k = n; k >= i; k--)
            {
                element_t temp;
                element_init_Zr(temp, pairing);
                element_mul(temp, s, matrix[ii][k]);             // temp = s * matrix[ii][k]
                element_sub(matrix[jj][k], matrix[jj][k], temp); // matrix[jj][k] -= temp
                element_clear(temp);
            }
        }
    }

    if (ok)
    {
        for (j = n - 1; j >= 0; j--)
        {
            /* Backward substitution */
            element_set_si(s, 0); // s = 0

            for (k = j + 1; k < n; k++)
            {
                element_t temp;
                element_init_Zr(temp, pairing);
                element_mul(temp, w[k], matrix[row[j]][k]); // temp = w[k] * matrix[row[j]][k]
                element_add(s, s, temp);                    // s += temp
                element_clear(temp);
            }

            if (element_is0(matrix[row[j]][j]))
            {
                ok = false;
                break;
            }

            element_sub(w[j], matrix[row[j]][n], s);    // w[j] = matrix[row[j]][n] - s
            element_div(w[j], w[j], matrix[row[j]][j]); // w[j] /= matrix[row[j]][j]

            // 将结果调整到 [-order/2, order/2]
            element_t abs_wj;
            element_init_Zr(abs_wj, pairing);
            // element_abs(abs_wj, w[j]); // abs_wj = abs(w[j])
            if (element_compare_to_zero(abs_wj) < 0)
            {
                element_neg(abs_wj, w[j]);
            }
            if (element_compare(abs_wj, half_order) > 0)
            {
                if (element_compare_to_zero(w[j]) < 0)
                {                                   // w[j] < 0
                    element_add(w[j], w[j], order); // w[j] += order
                }
                else if (element_compare_to_zero(w[j]) > 0)
                {                                   // w[j] > 0
                    element_sub(w[j], w[j], order); // w[j] -= order
                }
            }

            element_clear(abs_wj);
        }
    }

    element_clear(s);
    element_clear(p);
    element_clear(half_order);
    element_clear(two);
    delete[] row;

    return ok;
}

// Given set of attributes and LSSS matrix, returns reconstruction constant numerators w and rows
// Note: Original LSSS matrix is destroyed. Returns TRUE if successful, FALSE otherwise.
bool reduce_LSSS(
    element_t &order,
    int &m,
    int &d,
    element_t **LSSS,
    int *attr,
    int *auth,
    int *rows,
    element_t *w,
    pairing_t pairing)
{
    int i, j, k, n, nattr = 0;
    element_t s, det;

    element_init_Zr(s, pairing); // Temporary variable
    element_init_Zr(det, pairing);

    // Count the number of attributes in the `auth` array
    while (auth[nattr] != 0)
        nattr++;

    // Find rows in LSSS that correspond to attributes in `auth`
    k = 0;
    for (i = 0; i < m; i++)
    {
        for (j = 0; j < nattr; j++)
        {
            if (attr[i] == auth[j])
            {
                rows[k++] = i;
                break;
            }
        }
    }
    m = k;

    // Find active rows of LSSS and remove redundant ones
    for (i = 0; i < m; i++)
    {
        if (rows[i] == i)
            continue; // If the row is already in the correct place, skip it
        for (j = 0; j < d; j++)
        {
            element_set(LSSS[i][j], LSSS[rows[i]][j]); // Copy row content
        }
        attr[i] = attr[rows[i]]; // Update attribute for the new row
    }

    // Remove redundant columns (columns of all zeros) from LSSS
    int nzs; // Count of non-zero elements in the column
    for (j = 0; j < d; j++)
    {
        nzs = 0;
        for (i = 0; i < m; i++)
        {
            if (!element_is0(LSSS[i][j]))
            { // Check if column has non-zero elements
                nzs++;
                break;
            }
        }
        if (nzs != 0)
            continue; // If the column is not all zeros, skip it

        // Shift columns to the left to remove the zero column
        d--;
        for (i = 0; i < m; i++)
        {
            for (n = j; n < d; n++)
            {
                element_set(LSSS[i][n], LSSS[i][n + 1]);
            }
        }
    }

    // If the number of rows `m` is less than the number of columns `d`, reconstruction is impossible
    if (m < d)
    {
        element_clear(s);
        element_clear(det);
        return false;
    }

    // Calculate reconstruction constants
    // Transpose the matrix (swap rows and columns)
    for (i = 0; i < m; i++)
    {
        for (j = i + 1; j < m; j++)
        {
            element_set(s, LSSS[i][j]);
            element_set(LSSS[i][j], LSSS[j][i]);
            element_set(LSSS[j][i], s);
        }
    }
    // Use Gaussian elimination to solve the system of equations
    bool result = gauss(order, m, LSSS, w, pairing); // Assuming `gauss` has already been rewritten
    element_clear(s);
    element_clear(det);
    return result;
}
