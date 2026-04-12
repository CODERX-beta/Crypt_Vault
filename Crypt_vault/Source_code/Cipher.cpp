#include "Cipher.h"
#include <string>
using namespace std;

// ============================================================
//  SECTION 1 — POLYMORPHIC CIPHERS  (definitions)
// ============================================================

// ---- XORCipher ---------------------------------------------

XORCipher::XORCipher(char k) : key(k) {}

void XORCipher::applyXor(vector<char>& data) {
    for (char& c : data) c ^= key;
}

void XORCipher::encrypt(vector<char>& data) { applyXor(data); }
void XORCipher::decrypt(vector<char>& data) { applyXor(data); }

string XORCipher::name() const {
    return string("XOR  (key='") + key + "')";
}

// ---- CaesarCipher ------------------------------------------

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
