#include <iostream>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
using namespace std;
int main()
{
    string FileName = "input.txt"; // Название входного файла
    string outputHash; // Переменная для хранения результата хэширования

    SHA256 hash; // Выбираем алгоритм хэширования (SHA-256 в данном случае)
    FileSource(FileName.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(outputHash))));
    
    ifstream file(FileName);
	if (file.is_open()) { // Проверяем, успешно ли открыт файл
        string line;
        while (getline(file, line)) {
            cout << line << endl; // Выводим содержимое файла построчно
        }
    	file.close(); // Закрываем файл после чтения
   	} else {
        	cout << "Невозможно открыть файл " << FileName << std::endl;
    }
    cout << "Хэш файла " << FileName << ":\n";
    cout << outputHash << endl;

    return 0;
}
