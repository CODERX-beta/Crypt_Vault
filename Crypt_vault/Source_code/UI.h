#pragma once
#include "Cipher.h"
#include <memory>
#include <string>
using namespace std;

// ============================================================
//  SECTION 5 — UI HELPERS  (declarations)
// ============================================================

static const string VAULT_FILE = "vault.dat";

void printBanner();
void printMenu(const string& cipherName);
void flushCin();
string promptLine(const string& label);
unique_ptr<Cipher> chooseCipher();
