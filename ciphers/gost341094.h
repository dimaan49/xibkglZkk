#ifndef GOST341094_H
#define GOST341094_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

class GOST341094Cipher : public CipherInterface
{
public:
    GOST341094Cipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "ГОСТ Р 34.10-94 (ЭЦП)"; }
    QString description() const override {
        return "ГОСТ Р 34.10-94 — алгоритм электронной цифровой подписи "
               "на основе дискретного логарифмирования.";
    }

    bool isAvailable() const{ return true; }

    // Статические методы для генерации ключей
    static uint64_t generatePrimeStatic(int bits);
    static uint64_t generateRandomStatic(uint64_t max);
    static bool isPrimeStatic(uint64_t n, int k = 10);
    static uint64_t modPowStatic(uint64_t base, uint64_t exp, uint64_t mod);
    static uint64_t gcdStatic(uint64_t a, uint64_t b);

    // Методы для работы с числами
    uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) const;
    uint64_t modInverse(uint64_t a, uint64_t mod) const;
    uint64_t gcd(uint64_t a, uint64_t b) const;
    bool isPrime(uint64_t n, int k = 10) const;

    // Хеш-функция квадратичной свертки
    uint64_t computeHash(const QString& text, uint64_t p, QVector<CipherStep>& steps, int& stepCounter) const;

private:
    const QString m_alphabet = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

    // Преобразование текста в числа и обратно
    int charToNumber(QChar ch) const;
    QChar numberToChar(int num) const;
    QVector<uint64_t> textToNumbers(const QString& text) const;
    QString numbersToText(const QVector<uint64_t>& numbers) const;

    // Проверка параметров
    bool validateParameters(uint64_t p, uint64_t q, uint64_t a, uint64_t x, uint64_t k, uint64_t p_hash, QString& errorMessage) const;
};

// ==================== Регистратор ====================
class GOST341094CipherRegister
{
public:
    GOST341094CipherRegister();
};

#endif // GOST341094_H
