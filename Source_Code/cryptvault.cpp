#include "cryptvault.h"
#include <iostream>
#include <stdexcept>
#include <limits>
#include <cstdio>
using namespace std;

XORCipher::XORCipher(char k) : key(k) {}

void XORCipher::applyXor(vector<char>& data) {
    for (char& c : data) c ^= key;
}

void XORCipher::encrypt(vector<char>& data) { applyXor(data); }
void XORCipher::decrypt(vector<char>& data) { applyXor(data); }

string XORCipher::name() const {
    return string("XOR  (key='") + key + "')";
}

CaesarCipher::CaesarCipher(int s) : shift(s) {}

void CaesarCipher::encrypt(vector<char>& data) {
    for (char& c : data)
        c = static_cast<char>((static_cast<unsigned char>(c) + shift) % 256);
}

void CaesarCipher::decrypt(vector<char>& data) {
    for (char& c : data)
        c = static_cast<char>((static_cast<unsigned char>(c) - shift + 256) % 256);
}

string CaesarCipher::name() const {
    return "Caesar (shift=" + to_string(shift) + ")";
}

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

string AuthGuard::simpleHash(const string& s) {
    size_t h = 5381;
    for (unsigned char c : s) h = ((h << 5) + h) ^ c;
    return to_string(h);
}

AuthGuard::AuthGuard(const string& master, int attempts)
    : masterHash(simpleHash(master)), maxAttempts(attempts) {}

void AuthGuard::authenticate() const {
    for (int i = 1; i <= maxAttempts; ++i) {
        cout << "  Master password (attempt " << i << "/" << maxAttempts << "): ";
        string input;
        getline(cin, input);
        if (simpleHash(input) == masterHash) {
            cout << "  [Access granted]\n\n";
            return;
        }
        cout << "  [Wrong password]\n";
    }
    throw runtime_error("Too many failed attempts. Vault locked.");
}

void printBanner() {
    cout << "\n";
    cout << "  ╔══════════════════════════════════╗\n";
    cout << "  ║       C R Y P T V A U L T        ║\n";
    cout << "  ║     Secure Password Manager      ║\n";
    cout << "  ╚══════════════════════════════════╝\n\n";
}

void printMenu(const string& cipherName) {
    cout << "  Active cipher : " << cipherName << "\n";
    cout << "  ─────────────────────────────────\n";
    cout << "  1. Add credential\n";
    cout << "  2. View all credentials\n";
    cout << "  3. Search / view one credential\n";
    cout << "  4. Delete credential\n";
    cout << "  5. Save vault to disk\n";
    cout << "  6. Load vault from disk\n";
    cout << "  7. Switch cipher\n";
    cout << "  8. List services\n";
    cout << "  0. Exit\n";
    cout << "  ─────────────────────────────────\n";
    cout << "  Choice: ";
}

void flushCin() {
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

string promptLine(const string& label) {
    string val;
    while (val.empty()) {
        cout << "  " << label << ": ";
        getline(cin, val);
        if (val.empty()) cout << "  [Cannot be empty. Try again]\n";
    }
    return val;
}

unique_ptr<Cipher> chooseCipher() {
    cout << "\n  -- Select Cipher --\n";
    cout << "  1. XOR Cipher   (symmetric, fast)\n";
    cout << "  2. Caesar Cipher (shift-based)\n";
    cout << "  Choice: ";

    int choice = 0;
    cin >> choice;
    flushCin();

    if (choice == 1) {
        cout << "  Enter XOR key character (e.g. K): ";
        char k;
        cin >> k;
        flushCin();
        return make_unique<XORCipher>(k);
    } else {
        cout << "  Enter Caesar shift value (e.g. 7): ";
        int s = 5;
        cin >> s;
        flushCin();
        return make_unique<CaesarCipher>(s);
    }
}
