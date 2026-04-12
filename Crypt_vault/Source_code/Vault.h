#pragma once
#include "Cipher.h"
#include <map>
#include <vector>
#include <string>
using namespace std;

// ============================================================
//  SECTION 2 — TEMPLATE DataProtector  (header-only)
// ============================================================

template <typename T>
class DataProtector {
public:
    static vector<char> protect(const T& raw, Cipher& c) {
        vector<char> buffer(raw.begin(), raw.end());
        c.encrypt(buffer);
        return buffer;
    }
    static string recover(vector<char> buffer, Cipher& c) {
        c.decrypt(buffer);
        return string(buffer.begin(), buffer.end());
    }
};

// ============================================================
//  SECTION 3 — VAULT  (STL map + binary file I/O)
// ============================================================

class Vault {
    map<string, vector<char>> storage;
public:
    // ---- CRUD -----------------------------------------------
    void add(const string& service, vector<char>&& encrypted);
    bool remove(const string& service);
    bool exists(const string& service) const;
    bool empty() const;

    // ---- Display --------------------------------------------
    void listServices() const;
    void showAll(Cipher& c) const;
    void showOne(const string& service, Cipher& c) const;

    // ---- Persistence ----------------------------------------
    void save(const string& filename) const;
    void load(const string& filename);
};
