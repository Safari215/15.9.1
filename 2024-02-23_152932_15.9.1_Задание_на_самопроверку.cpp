/*
ЗАДАЧА: Модернизируйте модель чата из задания 15.4.2 так, чтобы логин и хеш от пароля теперь хранились в хеш-таблице. То есть логин является ключом, хеш — значением, а вместе они составляются пару. 
Хеш-функцию для хеш-таблицы составьте методом умножения. Хеш-таблицу реализуйте методом квадратичного пробирования.
Задание следует загрузить в свой репозиторий на GitHub.
Выполняя проект, обращайте внимание на следующие критерии:
- Выдержана структура проекта (файлы .h, .cpp).
- Необходимые структуры были разработаны согласно тематике задания.
- Выполняется принцип инкапсуляции.
- Решение полностью рабочее и соответствует требованиям в формулировке задания.
Большим плюсом будет решение проблемы (в любом виде) большого количества удаленных элементов в хеш-таблице
*/
// main.cpp
#include <iostream>
#include "sha1.h"
#include "chat.h"
#include <string.h>

void throwHere(const std::string& text) {
    std::cout << "Throw text: " << text.c_str() << std::endl;
    throw 1;
}

int main()
{
    bool good = false;
    setlocale(LC_CTYPE, "rus");
    try {

        
        Chat c;

        c.reg((char*)"user1", (char*)"qwerty12345", sizeof("qwerty12345"));
        c.reg((char*)"user2", (char*)"asdfg", sizeof("asdfg"));
        c.reg((char*)"user3", (char*)"zsdrt", sizeof("zsdrt"));
        c.reg((char*)"user4", (char*)"pasgas", sizeof("pasgas"));
        c.reg((char*)"dfd11111", (char*)"pasgas", sizeof("pasgas"));
        c.reg((char*)"sdgss", (char*)"pasgas", sizeof("pasgas"));
        c.reg((char*)"xzxvxcccc", (char*)"pasgas", sizeof("pasgas"));
        c.reg((char*)"123", (char*)"pasgas", sizeof("pasgas"));
        c.reg((char*)"34", (char*)"pasgas", sizeof("pasgas"));
        c.reg((char*)"111", (char*)"pasgas", sizeof("pasgas"));

        c.unreg((char*)"111");
        c.unreg((char*)"dfd11111");


        if (!c.login((char*)"user1", (char*)"qwerty12345", sizeof("qwerty12345")))  throwHere("in c.login() user1");
        if (!c.login((char*)"user2", (char*)"asdfg", sizeof("asdfg")))  throwHere("in c.login() user2");
        if (!c.login((char*)"user3", (char*)"zsdrt", sizeof("zsdrt")))  throwHere("in c.login() user3");
        if (!c.login((char*)"user3", (char*)"zsdrt", sizeof("zsdrt")))  throwHere("in c.login() user3");
        if (!c.login((char*)"user4", (char*)"pasgas", sizeof("pasgas")))  throwHere("in c.login() user4");
        if (!c.login((char*)"xzxvxcccc", (char*)"pasgas", sizeof("pasgas")))  throwHere("in c.login() xzxvxcccc");
        if (!c.login((char*)"123", (char*)"pasgas", sizeof("pasgas")))  throwHere("in c.login() 123");
        if (!c.login((char*)"34", (char*)"pasgas", sizeof("pasgas")))  throwHere("in c.login() 34");

        if (c.login((char*)"111", (char*)"pasgas", sizeof("pasgas")))  throwHere("in c.login() 111");
        if (c.login((char*)"dfd11111", (char*)"pasgas", sizeof("pasgas")))  throwHere("in c.login() dfd11111");

        if (c.login((char*)"user2", (char*)"qwerty12345", sizeof("qwerty12345"))) throwHere("in test() user2 bad pass");
        if (c.login((char*)"non-exuser", (char*)"pass", sizeof("pass"))) throwHere("in test() non-ex_user");

        good = true;
    }
    catch (...) {
        good = false;
    }

    if (good) {
        std::cout << "Тесты пройдены" << std::endl;
    }
    else {
        std::cout << "Тесты провалены" << std::endl;
    }
    return 0;
}
// chat.h
#pragma once

#include "sha1.h"
#include "string.h"


#define SIZE 10
#define LOGINLENGTH 10

class Chat {
public:
    Chat();
    void reg(char _login[LOGINLENGTH], char _pass[], int pass_length);
    bool login(char _login[LOGINLENGTH], char _pass[], int pass_length);
    void unreg(char _login[LOGINLENGTH]);

    friend void test(Chat& c);
private:

    enum CellStatus {
        free,
        engaged,
        deleted
    };

    struct AuthData {


        AuthData() :
            login(""),
            pass_sha1_hash(0),
            status(CellStatus::free) {
        }
        ~AuthData() {
            if (pass_sha1_hash != 0)
                delete[] pass_sha1_hash;
        }
        // копирует логин, забирает внутрь хеш
        AuthData(char _login[LOGINLENGTH], uint* sh1) {
            memcpy(login, _login, LOGINLENGTH);
            pass_sha1_hash = sh1;
            status = CellStatus::engaged;
        }
        // копирует всё
        AuthData& operator = (const AuthData& other) {
            memcpy(login, other.login, LOGINLENGTH);

            if (pass_sha1_hash != 0)
                delete[] pass_sha1_hash;
            pass_sha1_hash = new uint[SHA1HASHLENGTHUINTS];

            memcpy(pass_sha1_hash, other.pass_sha1_hash, SHA1HASHLENGTHBYTES);

            status = other.status;

            return *this;
        }
        char login[LOGINLENGTH];
        uint* pass_sha1_hash;

        CellStatus status;
    };

    void resize();
    void allocNewMem(int newMemSize);
    int hash_func(char login[LOGINLENGTH], int step);
    int hf_multiply(int val);
    void addinner(char login[LOGINLENGTH], uint* digest);

    AuthData* data;
    int data_count;
    int mem_size;
};
// chat.cpp
#include "chat.h"
#include "iostream"

Chat::Chat() {

    data_count = 0;
    data = nullptr;

    allocNewMem(8);
}
void Chat::reg(char _login[LOGINLENGTH], char _pass[], int pass_length) {
    uint* digest = sha1(_pass, pass_length);
    addinner(_login, digest);
}
void Chat::unreg(char _login[LOGINLENGTH]) {
    int index, i = 0;
    for (; i < mem_size; i++) {
        index = hash_func(_login, i*i);
        if (data[index].status == CellStatus::free)
            return;
        else if (data[index].status == CellStatus::engaged
            && !memcmp(_login, data[index].login, LOGINLENGTH))
            break;
    }
    if (i >= mem_size) return;

    data[index].status = CellStatus::deleted;
}
bool Chat::login(char _login[LOGINLENGTH], char _pass[], int pass_length) {

    int index, i = 0;
    for (; i < mem_size; i++) {
        index = hash_func(_login, i*i);
        if (data[index].status == CellStatus::free)
            return false;
        else if (data[index].status == CellStatus::engaged
            && !memcmp(_login, data[index].login, LOGINLENGTH))
            break;
    }
    if (i >= mem_size) return false;
    std::cout << "Propbs count: " << i + 1 << std::endl;

    uint* digest = sha1(_pass, pass_length);

    bool cmpHashes = !memcmp(
        data[index].pass_sha1_hash,
        digest,
        SHA1HASHLENGTHBYTES);
    delete[] digest;

    return cmpHashes;
}

void Chat::addinner(char login[LOGINLENGTH], uint* digest) {
    int index, i = 0;
    for (; i < mem_size; i++) {
        index = hash_func(login, i*i);
        if (data[index].status == CellStatus::free)
            break;
    }
    if (i >= mem_size)
    {
        resize();
        addinner(login, digest);
    }
    else {
        data[index] = AuthData(login, digest);
        data_count++;
    }
}

void Chat::allocNewMem(int newMemSize) {
    mem_size = newMemSize;
    data = new AuthData[mem_size];
}

int Chat::hash_func(char login[LOGINLENGTH], int step) {
    long sum = 0;
    for (int i = 0; i < LOGINLENGTH; i++) {
        sum += login[i];
    }
    return (hf_multiply(sum) + step) % mem_size;
}

int Chat::hf_multiply(int val) {
    const double A = 0.7;
    return int(mem_size * (A * val - int(A* val)));
}

void Chat::resize() {
    std::cout << "resize()" << endl;
    AuthData* save = data;
    int save_ms = mem_size;

    allocNewMem(mem_size * 2);
    data_count = 0;

    for (int i = 0; i < save_ms; i++) {
        AuthData& old_data = save[i];
        if (old_data.status == CellStatus::engaged) {

            uint* sha_hash_copy = new uint[SHA1HASHLENGTHUINTS];
            memcpy(sha_hash_copy, old_data.pass_sha1_hash, SHA1HASHLENGTHBYTES);

            addinner(old_data.login, sha_hash_copy);
        }
    }

    delete[] save;
}
// sha1.h
#pragma once

using namespace std;

typedef unsigned int uint;

#define one_block_size_bytes 64 // количество байб в блоке
#define one_block_size_uints 16 // количество 4байтовых  в блоке
#define block_expend_size_uints 80 // количество 4байтовых в дополненном блоке

#define SHA1HASHLENGTHBYTES 20
#define SHA1HASHLENGTHUINTS 5

typedef uint* Block;
typedef uint ExpendBlock[block_expend_size_uints];

const uint H[5] = {
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0
}; // константы, согласно стандарту

uint cycle_shift_left(uint val, int bit_count);
uint bring_to_human_view(uint val);

uint* sha1(char* message, uint msize_bytes); // отданный массив нужно удалить вручную
// sha1.cpp
#include "sha1.h"
#include <string.h>

uint cycle_shift_left(uint val, int bit_count) {
    return (val << bit_count | val >> (32 - bit_count));
}

uint bring_to_human_view(uint val) {
    return  ((val & 0x000000FF) << 24) |
        ((val & 0x0000FF00) << 8) |
        ((val & 0x00FF0000) >> 8) |
        ((val & 0xFF000000) >> 24);
}

uint* sha1(char* message, uint msize_bytes) {
    //инициализация
    uint A = H[0];
    uint B = H[1];
    uint C = H[2];
    uint D = H[3];
    uint E = H[4];

    // подсчет целого числа блоков
    uint totalBlockCount = msize_bytes / one_block_size_bytes;

    // подсчет, сколько байт нужно, чтобы дополнить последний блок
    uint needAdditionalBytes =
        one_block_size_bytes - (msize_bytes - totalBlockCount * one_block_size_bytes);

    if (needAdditionalBytes < 8) {
        totalBlockCount += 2;
        needAdditionalBytes += one_block_size_bytes;
    }
    else {
        totalBlockCount += 1;
    }

    // размер дополненного по всем правилам сообщения
    uint extendedMessageSize = msize_bytes + needAdditionalBytes;

    // выделяем новый буфер и копируем в него исходный
    unsigned char* newMessage = new unsigned char[extendedMessageSize];
    memcpy(newMessage, message, msize_bytes);

    // первый бит ставим '1', остальные обнуляем
    newMessage[msize_bytes] = 0x80;
    memset(newMessage + msize_bytes + 1, 0, needAdditionalBytes - 1);

    // задаем длину исходного сообщения в битах
    uint* ptr_to_size = (uint*)(newMessage + extendedMessageSize - 4);
    *ptr_to_size = bring_to_human_view(msize_bytes * 8);

    ExpendBlock exp_block;
    //раунды поехали
    for (int i = 0; i < totalBlockCount; i++) {

        // берем текущий блок и дополняем его
        unsigned char* cur_p = newMessage + one_block_size_bytes * i;
        Block block = (Block)cur_p;

        // первые 16 4байтовых чисел
        for (int j = 0; j < one_block_size_uints; j++) {
            exp_block[j] = bring_to_human_view(block[j]);
        }
        // следующие 64...
        for (int j = one_block_size_uints; j < block_expend_size_uints; j++) {
            exp_block[j] =
                exp_block[j - 3] ^
                exp_block[j - 8] ^
                exp_block[j - 14] ^
                exp_block[j - 16];
            exp_block[j] = cycle_shift_left(exp_block[j], 1);
        }

        // инициализация 
        uint a = H[0];
        uint b = H[1];
        uint c = H[2];
        uint d = H[3];
        uint e = H[4];

        // пересчитываем
        for (int j = 0; j < block_expend_size_uints; j++) {
            uint f;
            uint k;
            // в зависимости от раунда считаем по-разному
            if (j < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            // перемешивание
            uint temp = cycle_shift_left(a, 5) + f + e + k + exp_block[j];
            e = d;
            d = c;
            c = cycle_shift_left(b, 30);
            b = a;
            a = temp;
        }
        // пересчитываем
        A = A + a;
        B = B + b;
        C = C + c;
        D = D + d;
        E = E + e;
    }

    // A,B,C,D,E являются выходными 32б составляющими посчитанного хэша
    uint* digest = new uint[5];
    digest[0] = A;
    digest[1] = B;
    digest[2] = C;
    digest[3] = D;
    digest[4] = E;

    // чистим за собой
    delete[] newMessage;
    return digest;
}
// Повзаимствовал у автора модуля