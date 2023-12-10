#include <iostream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>

void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (CryptoPP::byte*)password.data(), password.size(), iv, iv.size(), 1000);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    std::ifstream ifs(inputFile, std::ios::binary);
    std::ofstream ofs(outputFile, std::ios::binary);

    CryptoPP::FileSource(ifs, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::FileSink(ofs)));
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (CryptoPP::byte*)password.data(), password.size(), iv, iv.size(), 1000);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    std::ifstream ifs(inputFile, std::ios::binary);
    std::ofstream ofs(outputFile, std::ios::binary);

    CryptoPP::FileSource(ifs, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::FileSink(ofs)));
}

int main()
{
    std::string inputFile, outputFile, password;
    int choice;

    std::cout << "Выберите режим работы (1 - зашифрование, 2 - расшифрование): ";
    std::cin >> choice;

    std::cout << "Введите имя входного файла: ";
    std::cin >> inputFile;

    std::cout << "Введите имя выходного файла: ";
    std::cin >> outputFile;

    std::cout << "Введите пароль: ";
    std::cin >> password;

    if (choice == 1)
    {
        encryptFile(inputFile, outputFile, password);
        std::cout << "Файл зашифрован." << std::endl;
    }
    else if (choice == 2)
    {
        decryptFile(inputFile, outputFile, password);
        std::cout << "Файл расшифрован." << std::endl;
    }
    else
    {
        std::cout << "Неправильный выбор режима работы." << std::endl;
        return 1;
    }

    return 0;
}
