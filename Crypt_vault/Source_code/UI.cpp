#include "UI.h"
#include <iostream>
#include <limits>
using namespace std;


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

// Flush leftover newline after numeric input
void flushCin() {
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

// Prompt for a non-empty string
string promptLine(const string& label) {
    string val;
    while (val.empty()) {
        cout << "  " << label << ": ";
        getline(cin, val);
        if (val.empty()) cout << "  [Cannot be empty. Try again]\n";
    }
    return val;
}

// Cipher selection submenu
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
