#include "parse.h"
#include <bits/stdc++.h>
using namespace std;

// ---------- AST_Node 构造函数实现 ----------
AST_Node::AST_Node(const string &a) : is_leaf(true), attr(a), op(0) {}
AST_Node::AST_Node(int op_, const vector<AST_Node*> &c) : is_leaf(false), op(op_), children(c) {}

// ---------- ExpressionParser 成员函数实现 ----------
vector<string> ExpressionParser::tokenize(const string &s) {
    vector<string> ts;
    int n = s.size(), i = 0;
    while (i < n) {
        if (isspace(s[i])) { i++; continue; }
        if (s[i] == '(' || s[i] == ')') {
            ts.emplace_back(1, s[i]); i++;
        } else {
            int j = i;
            while (j < n && !isspace(s[j]) && s[j] != '(' && s[j] != ')') j++;
            ts.push_back(s.substr(i, j - i)); i = j;
        }
    }
    return ts;
}

AST_Node* ExpressionParser::parse_expr() {
    vector<AST_Node*> terms;
    terms.push_back(parse_term());
    while (pos < tokens.size()) {
        string up = tokens[pos];
        transform(up.begin(), up.end(), up.begin(), ::toupper);
        if (up == "OR") { pos++; terms.push_back(parse_term()); }
        else break;
    }
    if (terms.size() == 1) return terms[0];
    return new AST_Node(1, terms);
}

AST_Node* ExpressionParser::parse_term() {
    vector<AST_Node*> facts;
    facts.push_back(parse_factor());
    while (pos < tokens.size()) {
        string up = tokens[pos];
        transform(up.begin(), up.end(), up.begin(), ::toupper);
        if (up == "AND") { pos++; facts.push_back(parse_factor()); }
        else break;
    }
    if (facts.size() == 1) return facts[0];
    return new AST_Node(2, facts);
}

AST_Node* ExpressionParser::parse_factor() {
    if (tokens[pos] == "(") {
        pos++;
        AST_Node* e = parse_expr();
        if (pos < tokens.size() && tokens[pos] == ")") pos++;
        return e;
    }
    return new AST_Node(tokens[pos++]);
}

AST_Node* ExpressionParser::parse(const string &expr) {
    string s = expr;
    auto trim = [](const string &str){
        size_t b = str.find_first_not_of(" \t\n\r");
        size_t e = str.find_last_not_of(" \t\n\r");
        return (b==string::npos? string(): str.substr(b, e-b+1));
    };
    s = trim(s);
    if (s.front() != '(' || s.back() != ')') {
        s = "(" + s + ")";
    }
    tokens = tokenize(s);
    pos = 0;
    return parse_expr();
}

ExpressionParser::ExpressionParser() = default;
ExpressionParser::~ExpressionParser() = default;

// ---------- AccessConverter 成员函数实现 ----------
AccessConverter::AccessConverter(const unordered_map<string, int>& mapping) : attr2id(mapping) {}
AccessConverter::~AccessConverter() = default;

vector<string> AccessConverter::convert(AST_Node* root) {
    vector<AST_Node*> internals;
    collect_internal(root, internals);
    unordered_map<AST_Node*, int> idx;
    for (int i = 0; i < internals.size(); ++i) idx[internals[i]] = i;

    vector<string> out;
    for (auto* AST_Node: internals) {
        int n = AST_Node->children.size();
        int t = (AST_Node->op == 2 ? n : 1);
        out.push_back(to_string(n));
        out.push_back(to_string(t));
        for (auto* ch: AST_Node->children) {
            if (ch->is_leaf) {
                auto it = attr2id.find(ch->attr);
                if (it == attr2id.end()) {
                    cerr << "Error: attribute " << ch->attr << " not found in mapping!" << endl;
                    out.push_back("-0");
                } else {
                    out.push_back("-" + to_string(it->second));
                }
            } else {
                out.push_back(to_string(idx[ch]));
            }
        }
    }
    out.push_back("0");
    return out;
}

const unordered_map<string, int>& AccessConverter::getAttrMapping() const {
    return attr2id;
}

void AccessConverter::collect_internal(AST_Node* root, vector<AST_Node*> &AST_Nodes) {
    if (!root || root->is_leaf) return;
    AST_Nodes.push_back(root);
    for (auto* ch: root->children) collect_internal(ch, AST_Nodes);
}

// ---------- Utility ----------
void print_access(const vector<string> &arr) {
    for (int i = 0; i < arr.size(); ++i) {
        cout << arr[i] << (i + 1 < arr.size() ? "," : "\n");
    }
}

std::string access_to_string(const std::vector<std::string> &arr) {
    std::string result;
    for (size_t i = 0; i < arr.size(); ++i) {
        result += arr[i];
        if (i + 1 < arr.size()) result += ",";
    }
    return result;
}
