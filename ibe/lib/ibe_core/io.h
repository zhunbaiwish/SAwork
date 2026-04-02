#ifndef IO_H
#define IO_H
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <cerrno>

static bool write_file(const std::string &path, const uint8_t *buf, size_t len) {
    if (!buf) {
        std::cerr << "write_file: buf == nullptr, path=" << path << " len=" << len << "\n";
        return false;
    }
    if (len == 0) {
        std::cerr << "write_file: len == 0, path=" << path << "\n";
        return false;
    }
    FILE *fp = fopen(path.c_str(), "wb");
    if (!fp) {
        std::cerr << "write_file: fopen failed for path=" << path << " errno=" << errno
                  << " (" << std::strerror(errno) << ")\n";
        return false;
    }
    size_t w = fwrite(buf, 1, len, fp);
    if (w != len) {
        std::cerr << "write_file: fwrite wrote " << w << " of " << len
                  << " errno=" << errno << " (" << std::strerror(errno) << ")\n";
    }
    fclose(fp);
    return w == len;
}

static bool read_file(const std::string &path, std::vector<uint8_t> &out) {
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return false; }
    out.resize((size_t)sz);
    size_t r = fread(out.data(), 1, out.size(), fp);
    fclose(fp);
    return r == out.size();
}
#endif // IO_H