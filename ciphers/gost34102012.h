#ifndef GOST34102012_H
#define GOST34102012_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>
#include <vector>
#include <string>

// ==================== Big Integer для 512-битных чисел ====================
class BigInt {
private:
    std::vector<uint64_t> limbs;
    static const int BITS_PER_LIMB = 64;

    void normalize();

public:
    BigInt();
    BigInt(uint64_t value);
    BigInt(const std::string& hex);
    BigInt(const QByteArray& bytes);

    bool isZero() const;
    bool isOne() const;
    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;
    bool operator<(const BigInt& other) const;
    bool operator<=(const BigInt& other) const;
    bool operator>(const BigInt& other) const;
    bool operator>=(const BigInt& other) const;

    BigInt operator+(const BigInt& other) const;
    BigInt operator-(const BigInt& other) const;
    BigInt operator*(const BigInt& other) const;
    BigInt operator/(const BigInt& other) const;
    BigInt operator%(const BigInt& other) const;
    BigInt& operator+=(const BigInt& other);
    BigInt& operator-=(const BigInt& other);
    BigInt& operator*=(const BigInt& other);
    BigInt& operator/=(const BigInt& other);
    BigInt& operator%=(const BigInt& other);

    BigInt modPow(const BigInt& exp, const BigInt& mod) const;
    BigInt modInverse(const BigInt& mod) const;

    std::string toHex() const;
    QString toQString() const;
    uint64_t toUInt64() const;

    int bitLength() const;

    static BigInt random(int bits);
    static BigInt random(const BigInt& max);
};

// ==================== Точка эллиптической кривой ====================
struct ECPoint {
    BigInt x;
    BigInt y;
    bool isInfinity;

    ECPoint();
    ECPoint(const BigInt& x_, const BigInt& y_);

    bool operator==(const ECPoint& other) const;
    bool operator!=(const ECPoint& other) const;

    QString toString() const;
};

// ==================== GOST34102012Cipher ====================
class GOST34102012Cipher : public CipherInterface
{
public:
    GOST34102012Cipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "ГОСТ Р 34.10-2012 (ЭЦП на эллиптических кривых)"; }
    QString description() const override {
        return "ГОСТ Р 34.10-2012 — алгоритм электронной цифровой подписи "
               "на основе эллиптических кривых (ECDSA).";
    }

    // Статические методы для генерации ключей
    static BigInt generatePrimeStatic(int bits);
    static BigInt generateRandomStatic(const BigInt& max);

    // Арифметика эллиптической кривой
    static ECPoint pointAdd(const ECPoint& P, const ECPoint& Q, const BigInt& p, const BigInt& a);
    static ECPoint pointDouble(const ECPoint& P, const BigInt& p, const BigInt& a);
    static ECPoint pointMul(const BigInt& k, const ECPoint& P, const BigInt& p, const BigInt& a);

    // Хеш-функция квадратичной свертки
    BigInt computeHash(const QString& text, const BigInt& p, QVector<CipherStep>& steps, int& stepCounter) const;

private:
    const QString m_alphabet = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

    // Преобразование текста в числа
    QVector<uint64_t> textToNumbers(const QString& text) const;
    QString numbersToText(const QVector<uint64_t>& numbers) const;
    int charToNumber(QChar ch) const;
    QChar numberToChar(int num) const;

    // Проверка параметров
    bool validateParameters(const BigInt& p, const BigInt& a, const BigInt& b,
                           const BigInt& q, const ECPoint& P, QString& errorMessage) const;

    // Преобразование строки в BigInt
    BigInt parseBigInt(const QString& str) const;
};

// ==================== Регистратор ====================
class GOST34102012CipherRegister
{
public:
    GOST34102012CipherRegister();
};

#endif // GOST34102012_H
