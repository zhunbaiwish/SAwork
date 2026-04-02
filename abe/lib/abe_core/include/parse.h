// parse.h
#ifndef PARSE_H
#define PARSE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>

// ---------- AST Node ----------
struct AST_Node {
    bool is_leaf;
    std::string attr;
    int op; // 1=OR, 2=AND
    std::vector<AST_Node*> children;
    AST_Node(const std::string &a);
    AST_Node(int op_, const std::vector<AST_Node*> &c);
};

// ---------- Parser Interface ----------
class IExpressionParser {
public:
    virtual ~IExpressionParser() {}
    virtual AST_Node* parse(const std::string &expr) = 0;
};

// ---------- Expression Parser ----------
class ExpressionParser : public IExpressionParser {
public:
    ExpressionParser();
    virtual ~ExpressionParser() override;
    AST_Node* parse(const std::string &expr) override;

private:
    std::vector<std::string> tokenize(const std::string &s); // ← 添加这一行
    AST_Node* parse_expr();
    AST_Node* parse_term();
    AST_Node* parse_factor();
    std::vector<std::string> tokens;
    size_t pos;
};

// ---------- Converter Interface ----------
class IAccessConverter {
public:
    virtual ~IAccessConverter() = default;  // 改成 default
    virtual std::vector<std::string> convert(AST_Node* root) = 0;
};

// ---------- ACCESS Converter Implementation ----------
class AccessConverter : public IAccessConverter {
private:
    std::unordered_map<std::string, int> attr2id;
    void collect_internal(AST_Node* root, std::vector<AST_Node*> &AST_Nodes); // ← 添加这一行

public:
    AccessConverter(const std::unordered_map<std::string, int>& mapping);
    virtual ~AccessConverter() override;
    std::vector<std::string> convert(AST_Node* root) override;
    const std::unordered_map<std::string, int>& getAttrMapping() const;
};

// ---------- Utility to print/access ACCESS array ----------
void print_access(const std::vector<std::string> &arr);
std::string access_to_string(const std::vector<std::string> &arr);

#endif