#pragma once
#include <vector>
#include <string>
#include <map>
#include <memory>
using namespace std;

class Cipher {
public:
    virtual void   encrypt(vector<char>& data) = 0;
    virtual void   decrypt(vector<char>& data) = 0;
    virtual string name() const = 0;
    virtual ~Cipher() = default;
};

class XORCipher : public Cipher {
    char key;
public:
    explicit XORCipher(char k = 'K');
    void   encrypt(vector<char>& data) override;
    void   decrypt(vector<char>& data) override;
    string name() const override;
private:
    void applyXor(vector<char>& data);
};

class CaesarCipher : public Cipher {
    int shift;
public:
    explicit CaesarCipher(int s = 5);
    void   encrypt(vector<char>& data) override;
    void   decrypt(vector<char>& data) override;
    string name() const override;
};

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

class Vault {
    map<string, vector<char>> storage;
public:
    void add(const string& service, vector<char>&& encrypted);
    bool remove(const string& service);
    bool exists(const string& service) const;
    bool empty() const;
    void listServices() const;
    void showAll(Cipher& c) const;
    void showOne(const string& service, Cipher& c) const;
    void save(const string& filename) const;
    void load(const string& filename);
};

class AuthGuard {
    string masterHash;
    int    maxAttempts;
    static string simpleHash(const string& s);
public:
    explicit AuthGuard(const string& master, int attempts = 3);
    void authenticate() const;
};

static const string VAULT_FILE = "vault.dat";

void printBanner();
void printMenu(const string& cipherName);
void flushCin();
string promptLine(const string& label);
unique_ptr<Cipher> chooseCipher();
