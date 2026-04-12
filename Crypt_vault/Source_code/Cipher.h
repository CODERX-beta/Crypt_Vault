#pragma once
#include <vector>
#include <string>
using namespace std;

// ============================================================
//  SECTION 1 — POLYMORPHIC CIPHERS  (declarations)
// ============================================================

class Cipher {
public:
    virtual void   encrypt(vector<char>& data) = 0;
    virtual void   decrypt(vector<char>& data) = 0;
    virtual string name()   const = 0;
    virtual ~Cipher() = default;
};

class XORCipher : public Cipher {
    char key;
public:
    explicit XORCipher(char k = 'K');
    void   encrypt(vector<char>& data) override;
    void   decrypt(vector<char>& data) override;
    string name()   const override;
private:
    void applyXor(vector<char>& data);
};

class CaesarCipher : public Cipher {
    int shift;
public:
    explicit CaesarCipher(int s = 5);
    void   encrypt(vector<char>& data) override;
    void   decrypt(vector<char>& data) override;
    string name()   const override;
};
