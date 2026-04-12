#include "AuthGuard.h"
#include <iostream>
#include <stdexcept>
using namespace std;

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
