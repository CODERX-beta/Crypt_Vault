#pragma once
#include <string>
using namespace std;

class AuthGuard {
    string masterHash;
    int    maxAttempts;

    static string simpleHash(const string& s);
public:
    explicit AuthGuard(const string& master, int attempts = 3);
    void authenticate() const;
};
