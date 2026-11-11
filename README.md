# password-audit-cpp ⚡

Password strength auditor in C++20 with OpenSSL.

## Features
- Entropy calculation
- Pattern detection (common sequences, repeats)
- HIBP SHA-1 prefix for k-anonymity check
- Batch mode from file

## Build
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/password_audit "MyP@ssw0rd!"
./build/password_audit -f passwords.txt
```

## License
MIT
