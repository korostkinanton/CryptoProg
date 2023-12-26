#include <iostream>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
using namespace std;

void EncryptFile(const string& inputFileName, const string& outputFileName, const string& password) {
    AutoSeededRandomPool rnd;
    SecByteBlock key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE);  // Создание блочных массивов для хранения ключа и IV
    rnd.GenerateBlock(key, key.size());
    rnd.GenerateBlock(iv, iv.size());

    string encoded;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encoded))); // Преобразование ключа в строку в шестнадцатеричном формате
    ofstream keyFile("key.txt");
    keyFile << encoded; //Запись
    keyFile.close();

    string encodedIV;
    StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(encodedIV)));
    ofstream IVFile("iv.txt");
    IVFile << encodedIV;
    IVFile.close();

    CBC_Mode<AES>::Encryption encryption(key, key.size(), iv); // Создание объекта для шифрования в режиме CBC с использованием ключа и IV
    FileSource(inputFileName.c_str(), true, // Чтение входного файла
        new StreamTransformationFilter(encryption,  // Применение шифрования
            new FileSink(outputFileName.c_str()) // Запись результатов в выходной файл
        )
    );
}

void DecryptFile(const string& inputFileName, const string& outputFileName, const string& password) {
    string encoded, encodedIV; // Переменные для хранения закодированного ключа и IV
    ifstream keyFile("key.txt");
    getline(keyFile, encoded); //Чтение
    keyFile.close();
    
    ifstream IVFile("iv.txt");
    getline(IVFile, encodedIV);
    IVFile.close();

    SecByteBlock key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE);
    StringSource(encoded, true, new HexDecoder(new ArraySink(key, key.size()))); // Декодирование ключа из строки в шестнадцатеричном формате
    StringSource(encodedIV, true, new HexDecoder(new ArraySink(iv, iv.size()))); // Декодирование IV из строки в шестнадцатеричном формате

    CBC_Mode<AES>::Decryption decryption(key, key.size(), iv); // Создание объекта для расшифровки в режиме CBC с использованием ключа и IV
    FileSource(inputFileName.c_str(), true,//Читаем
        new StreamTransformationFilter(decryption,//Принимаем расшифровку
            new FileSink(outputFileName.c_str())//Записываем
        )
    );
}

int main() {
    string mode, inputFileName, outputFileName, password;
    cout << "Выберите действие (1 - шифрование, 2 - расшифровка): ";
    cin >> mode;

    if (mode != "1" && mode != "2") {
        cerr << "Выбрано недопустимое действие!" << endl;
        return 1;
    }

    cout << "Введите имя входного файла: ";
    cin >> inputFileName;

    cout << "Введите имя выходного файла: ";
    cin >> outputFileName;

    cout << "Введите пароль: ";
    cin >> password;

    if (mode == "1") {
        EncryptFile(inputFileName, outputFileName, password);
        cout << "Файл зашифрован." << endl;
    } else {
        DecryptFile(inputFileName, outputFileName, password);
        cout << "Файл расшифрован." << endl;
    }

    return 0;
}
