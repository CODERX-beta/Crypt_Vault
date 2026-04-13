#include "cryptvault.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <stdexcept>
using namespace std;

static void runTests(const string& inputFile, Vault& vault, Cipher& cipher) {
    ifstream fin(inputFile);
    if (!fin) {
        cerr << "  [!] Cannot open test file: " << inputFile << "\n";
        return;
    }

    cout << "\n  ══════════════════════════════════════\n";
    cout << "   TEST MODE  —  file: " << inputFile << "\n";
    cout << "  ══════════════════════════════════════\n\n";

    int passed = 0, failed = 0, total = 0;

    auto result = [&](bool ok, const string& desc) {
        ++total;
        if (ok) { ++passed; cout << "  [PASS] " << desc << "\n"; }
        else    { ++failed; cout << "  [FAIL] " << desc << "\n"; }
    };

    vector<pair<string,string>> entries;
    string line;
    while (getline(fin, line)) {
        if (line.empty() || line[0] == '#') continue;
        istringstream iss(line);
        string svc, pass;
        if (iss >> svc >> pass) entries.emplace_back(svc, pass);
    }

    cout << "  Parsed " << entries.size() << " entr"
         << (entries.size() == 1 ? "y" : "ies") << " from file.\n\n";

    cout << "  -- TC1: Add credentials --\n";
    for (auto& [svc, pass] : entries) {
        vault.add(svc, DataProtector<string>::protect(pass, cipher));
        result(!vault.empty(), "Add '" + svc + "'");
    }
    cout << "\n";

    cout << "  -- TC2: Exists check --\n";
    for (auto& [svc, pass] : entries)
        result(vault.exists(svc), "Exists '" + svc + "'");
    result(!vault.exists("__nonexistent__"), "Non-existent key returns false");
    cout << "\n";

    cout << "  -- TC3: Encrypt -> Decrypt roundtrip --\n";
    for (auto& [svc, pass] : entries) {
        auto enc = DataProtector<string>::protect(pass, cipher);
        auto dec = DataProtector<string>::recover(enc, cipher);
        result(dec == pass, "Roundtrip '" + svc + "' ('" + pass + "')");
    }
    cout << "\n";

    cout << "  -- TC4: Save / Load roundtrip --\n";
    bool saveOk = false, loadOk = false;
    try { vault.save(VAULT_FILE); saveOk = true; } catch (...) {}
    result(saveOk, "Save vault to disk");

    Vault vault2;
    try { vault2.load(VAULT_FILE); loadOk = true; } catch (...) {}
    result(loadOk, "Load vault from disk");

    for (auto& [svc, pass] : entries)
        result(vault2.exists(svc), "Post-load exists '" + svc + "'");
    cout << "\n";

    cout << "  -- TC5: Delete credentials --\n";
    for (auto& [svc, pass] : entries) {
        bool removed = vault.remove(svc);
        result(removed,            "Remove '" + svc + "' returns true");
        result(!vault.exists(svc), "'" + svc + "' gone after remove");
    }
    result(!vault.remove("__nonexistent__"), "Remove non-existent returns false");
    cout << "\n";

    cout << "  -- TC6: Vault empty after all deletes --\n";
    result(vault.empty(), "Vault is empty");
    cout << "\n";

    cout << "  ══════════════════════════════════════\n";
    cout << "   Results: " << passed << "/" << total << " passed";
    if (failed) cout << "  (" << failed << " failed)";
    cout << "\n";
    cout << "  ══════════════════════════════════════\n\n";
}

int main(int argc, char* argv[]) {
    printBanner();

    AuthGuard guard("SecureMaster99");
    try {
        guard.authenticate();
    } catch (const runtime_error& e) {
        cerr << "\n  [!] " << e.what() << "\n";
        return 1;
    }

    unique_ptr<Cipher> cipher = make_unique<CaesarCipher>(7);
    Vault vault;
    bool  saved = true;

    if (argc == 2) {
        runTests(argv[1], vault, *cipher);
        return 0;
    }

    try {
        vault.load(VAULT_FILE);
        saved = true;
        cout << "  [Auto-loaded vault from " << VAULT_FILE << "]\n\n";
    } catch (const runtime_error&) {
        cout << "  [No existing vault found — starting fresh]\n\n";
    }

    int choice = -1;
    while (choice != 0) {
        printMenu(cipher->name());
        cin >> choice;
        flushCin();

        switch (choice) {

        case 1: {
            string svc  = promptLine("Service name (e.g. GitHub)");
            string pass = promptLine("Password");
            if (vault.exists(svc)) {
                cout << "  [!] Service already exists. Overwrite? (y/n): ";
                char c; cin >> c; flushCin();
                if (c != 'y' && c != 'Y') { cout << "  [Cancelled]\n"; break; }
            }
            vault.add(svc, DataProtector<string>::protect(pass, *cipher));
            cout << "  [+] '" << svc << "' added.\n";
            saved = false;
            break;
        }

        case 2:
            cout << "\n  -- All Credentials --\n";
            vault.showAll(*cipher);
            break;

        case 3: {
            string svc = promptLine("Service name");
            vault.showOne(svc, *cipher);
            break;
        }

        case 4: {
            cout << "\n  -- Stored Services --\n";
            vault.listServices();
            if (vault.empty()) break;
            string svc = promptLine("Service to delete");
            if (vault.remove(svc)) {
                cout << "  [-] '" << svc << "' deleted.\n";
                saved = false;
            } else {
                cout << "  [!] Service not found.\n";
            }
            break;
        }

        case 5:
            try {
                vault.save(VAULT_FILE);
                saved = true;
                cout << "  [Saved to " << VAULT_FILE << "]\n";
            } catch (const runtime_error& e) {
                cerr << "  [!] " << e.what() << "\n";
            }
            break;

        case 6: {
            if (!saved) {
                cout << "  [!] Unsaved changes will be lost. Continue? (y/n): ";
                char c; cin >> c; flushCin();
                if (c != 'y' && c != 'Y') { cout << "  [Cancelled]\n"; break; }
            }
            try {
                vault.load(VAULT_FILE);
                saved = true;
                cout << "  [Loaded from " << VAULT_FILE << "]\n";
            } catch (const runtime_error& e) {
                cerr << "  [!] " << e.what() << "\n";
            }
            break;
        }

        case 7: {
            if (!vault.empty()) {
                cout << "\n  [!] WARNING: Switching cipher does NOT re-encrypt\n"
                     << "      existing entries. They must be re-added with\n"
                     << "      the new cipher or loaded from disk first.\n";
                cout << "  Proceed? (y/n): ";
                char c; cin >> c; flushCin();
                if (c != 'y' && c != 'Y') { cout << "  [Cancelled]\n"; break; }
            }
            cipher = chooseCipher();
            cout << "  [Cipher set to: " << cipher->name() << "]\n";
            break;
        }

        case 8:
            cout << "\n  -- Stored Services --\n";
            vault.listServices();
            break;

        case 0:
            if (!saved) {
                cout << "  [!] You have unsaved changes. Save before exit? (y/n): ";
                char c; cin >> c; flushCin();
                if (c == 'y' || c == 'Y') {
                    try {
                        vault.save(VAULT_FILE);
                        cout << "  [Saved]\n";
                    } catch (const runtime_error& e) {
                        cerr << "  [!] " << e.what() << "\n";
                    }
                }
            }
            cout << "\n  [Vault closed. Goodbye.]\n\n";
            break;

        default:
            cout << "  [!] Invalid option. Please enter 0-8.\n";
        }

        cout << "\n";
    }

    return 0;
}
