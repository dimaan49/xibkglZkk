#ifndef DIFFIEHELLMAN_H
#define DIFFIEHELLMAN_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

class DiffieHellmanCipher : public CipherInterface
{
public:
    DiffieHellmanCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "Диффи-Хеллман (обмен ключами)"; }
    QString description() const override {
        return "Протокол обмена ключами Диффи-Хеллмана. "
               "Позволяет двум сторонам выработать общий секретный ключ "
               "через незащищенный канал связи.";
    }


    // Статические методы для генерации
    static uint64_t generatePrimeStatic(int bits);
    static uint64_t generateRandomStatic(uint64_t max);
    static bool isPrimeStatic(uint64_t n, int k = 10);
    static uint64_t modPowStatic(uint64_t base, uint64_t exp, uint64_t mod);
    static uint64_t gcdStatic(uint64_t a, uint64_t b);

    // Методы для работы с числами
    uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) const;
    uint64_t gcd(uint64_t a, uint64_t b) const;
    bool isPrime(uint64_t n, int k = 10) const;

private:
    const QString m_alphabet = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
};

// ==================== Регистратор ====================
class DiffieHellmanCipherRegister
{
public:
    DiffieHellmanCipherRegister();
};

#endif // DIFFIEHELLMAN_H
