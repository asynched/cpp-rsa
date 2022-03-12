#include <iostream>
#include <vector>
#include <ctime>

#include "utils/math.h"
#include "core/encryption.h"

static std::vector<uint64_t> primes = math::generate_primes(10000);

int main(void)
{
    std::srand(std::time(NULL));

    auto encryption = RSAKey::from(primes);

    std::string message;

    std::cout << "Type in a message: ";
    std::getline(std::cin, message);

    auto encrypted = encryption.encrypt(message);
    std::cout << encrypted << std::endl;

    auto decrypted = encryption.decrypt(encrypted);
    std::cout << decrypted << std::endl;
}
