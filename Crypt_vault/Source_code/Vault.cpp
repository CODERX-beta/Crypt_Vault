#include "Vault.h"
#include <iostream>
#include <stdexcept>
#include <cstdio>
using namespace std;

// ============================================================
//  SECTION 3 — VAULT  (definitions)
// ============================================================

// ---- CRUD --------------------------------------------------

void Vault::add(const string& service, vector<char>&& encrypted) {
    storage[service] = move(encrypted);
}

bool Vault::remove(const string& service) {
    return storage.erase(service) > 0;
}

bool Vault::exists(const string& service) const {
    return storage.count(service) > 0;
}

bool Vault::empty() const { return storage.empty(); }

// ---- Display -----------------------------------------------

void Vault::listServices() const {
    if (storage.empty()) {
        cout << "  (no entries)\n";
        return;
    }
    int i = 1;
    for (const auto& [svc, _] : storage)
        cout << "  " << i++ << ". " << svc << "\n";
}

void Vault::showAll(Cipher& c) const {
    if (storage.empty()) { cout << "  (vault is empty)\n"; return; }
    cout << "\n";
    for (const auto& [svc, buf] : storage) {
        vector<char> copy = buf;
        cout << "  Service  : " << svc << "\n"
             << "  Password : "
             << DataProtector<string>::recover(move(copy), c)
             << "\n\n";
    }
}

void Vault::showOne(const string& service, Cipher& c) const {
    auto it = storage.find(service);
    if (it == storage.end()) {
        cout << "  [!] Service not found.\n";
        return;
    }
    vector<char> copy = it->second;
    cout << "  Service  : " << service << "\n"
         << "  Password : "
         << DataProtector<string>::recover(move(copy), c)
         << "\n";
}

// ---- Persistence -------------------------------------------

void Vault::save(const string& filename) const {
    FILE* f = fopen(filename.c_str(), "wb");
    if (!f) throw runtime_error("Cannot open file for writing: " + filename);
    for (const auto& [name, buf] : storage) {
        size_t nLen = name.size(), bLen = buf.size();
        fwrite(&nLen,       sizeof(size_t), 1,    f);
        fwrite(name.data(), sizeof(char),   nLen, f);
        fwrite(&bLen,       sizeof(size_t), 1,    f);
        fwrite(buf.data(),  sizeof(char),   bLen, f);
    }
    fclose(f);
}

void Vault::load(const string& filename) {
    FILE* f = fopen(filename.c_str(), "rb");
    if (!f) throw runtime_error("Vault file not found: " + filename);
    storage.clear();
    size_t nLen = 0, bLen = 0;
    while (fread(&nLen, sizeof(size_t), 1, f) == 1) {
        if (nLen == 0 || nLen > 1024)
            throw runtime_error("Corrupt vault: invalid name length");
        string name(nLen, '\0');
        if (fread(name.data(), 1, nLen, f) != nLen)
            throw runtime_error("Corrupt vault: truncated name");
        if (fread(&bLen, sizeof(size_t), 1, f) != 1)
            throw runtime_error("Corrupt vault: missing buffer length");
        if (bLen > 65536)
            throw runtime_error("Corrupt vault: oversized buffer");
        vector<char> buf(bLen);
        if (fread(buf.data(), 1, bLen, f) != bLen)
            throw runtime_error("Corrupt vault: truncated buffer");
        storage[name] = move(buf);
    }
    fclose(f);
}
