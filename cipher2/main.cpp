#include <iostream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>

using namespace CryptoPP;

void DeriveKey(const std::string& password, SecByteBlock& derivedKey, SecByteBlock& iv) {
    const int KEY_SIZE = AES::DEFAULT_KEYLENGTH;
    const int IV_SIZE = AES::BLOCKSIZE;

    MD5 hash; //Создается объект MD5, который будет использоваться для вычисления хеша пароля.
    SecByteBlock digest(hash.DigestSize()); //Создается блок для хранения хеша пароля (digest)
    hash.Update((const byte*)password.data(), password.size());
    hash.Final(digest);
    //Пароль обновляется в объекте MD5.

    std::memcpy(derivedKey, digest, KEY_SIZE);
    std::memcpy(iv, digest + KEY_SIZE, IV_SIZE);
    //Полученный хеш пароля используется для заполнения ключа и IV с помощью функции memcpy.
}

void EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);
	// Создаются объекты key и iv типа SecByteBlock для хранения ключа и вектора инициализации.
    DeriveKey(password, key, iv); //Функция DeriveKey вызывается для генерации ключа и вектора инициализации на основе пароля.

    CBC_Mode<AES>::Encryption encryption; //Создается объект CBC_Mode<AES>::Encryption encryption для представления шифрования в режиме CBC.
    encryption.SetKeyWithIV(key, key.size(), iv); //Устанавливаются ключ и вектор инициализации для объекта encryption с помощью метода SetKeyWithIV

    FileSource fs(inputFile.c_str(), true, new StreamTransformationFilter(encryption, new FileSink(outputFile.c_str()))); //Создается объект FileSource для чтения исходного файла и объект FileSink для записи зашифрованных данных. Запускается процесс шифрования с использованием объекта encryption и созданных объектов FileSource и FileSink
}

void DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    DeriveKey(password, key, iv);

    CBC_Mode<AES>::Decryption decryption; //Создается объект CBC_Mode<AES>::Decryption decryption для представления расшифрования в режиме CBC.
    decryption.SetKeyWithIV(key, key.size(), iv); //Устанавливаются ключ и вектор инициализации для объекта decryption с помощью метода SetKeyWithIV

    FileSource fs(inputFile.c_str(), true, new StreamTransformationFilter(decryption, new FileSink(outputFile.c_str()))); //Запускается процесс расшифрования с использованием объекта decryption и созданных объектов FileSource и FileSink
}

int main() {
    int choice;
    std::string inputFile, outputFile, password;

    std::cout << "1 - зашифровка, 2 - расшировка ";
    std::cin >> choice;

    std::cout << "Введите имя входного файла ";
    std::cin >> inputFile;

    std::cout << "Введите имя выходного файла ";
    std::cin >> outputFile;

    std::cout << "Введите пароль ";
    std::cin >> password;

    if (choice == 1) {
        EncryptFile(inputFile, outputFile, password);
        std::cout << "Файл зашифрован" << std::endl;
    } else if (choice == 2) {
        DecryptFile(inputFile, outputFile, password);
        std::cout << "Файл расшифрован" << std::endl;
    } else {
        std::cout << "Некоректный режим работы" << std::endl;
    }

    return 0;
}
