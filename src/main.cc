#include <ctime>
#include <iostream>
#include <vector>

#include "core/encryption.h"
#include "utils/math.h"

static std::vector<uint64_t> primes = math::generate_primes(10000);

int main(void) {
    using namespace encryption;
    std::srand(std::time(NULL));

    auto encryption = RSAEncryption::from(primes);

    while (1) {
        std::string message;

        std::cout << "[PROMPT] Type in a message: ";
        std::getline(std::cin, message);

        auto encrypted = encryption.encrypt(message);
        std::cout << "[ENCRYPTED] " << encrypted << std::endl;

        auto decrypted = encryption.decrypt(encrypted);
        std::cout << "[DECRYPTED] " << decrypted << std::endl << std::endl;
    }
}
