#ifndef ELGAMALSIGN_H
#define ELGAMALSIGN_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

// ==================== ElGamalSignCipher ====================
class ElGamalSignCipher : public CipherInterface
{
public:
    ElGamalSignCipher();

    // Основные методы шифрования/расшифрования
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "ElGamal с цифровой подписью"; }
    QString description() const override {
        return "Алгоритм ElGamal с цифровой подписью. "
               "При шифровании создается подпись сообщения (a,b), "
               "при расшифровании подпись проверяется.";
    }

    // Статические методы для генерации ключей
    static uint64_t generatePrimeStatic(int bits);
    static uint64_t generatePrimitiveRootStatic(uint64_t p);
    static uint64_t generateRandomKStatic(uint64_t p);
    static uint64_t modPowStatic(uint64_t base, uint64_t exp, uint64_t mod);
    static uint64_t gcdStatic(uint64_t a, uint64_t b);
    static bool isPrimeStatic(uint64_t n, int k = 10);

    // Методы для работы с числами
    uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) const;
    uint64_t modInverse(uint64_t a, uint64_t mod) const;
    uint64_t gcd(uint64_t a, uint64_t b) const;
    bool isPrime(uint64_t n, int k = 10) const;
    bool isPrimitiveRoot(uint64_t g, uint64_t p) const;

    // Хеш-функция квадратичной свертки
    uint64_t computeHash(const QString& text, uint64_t p, QVector<CipherStep>& steps, int stepOffset) const;

private:
    const QString m_alphabet = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

    // Проверка параметров
    bool validateParameters(uint64_t p, uint64_t g, uint64_t x, uint64_t p_hash, QString& errorMessage) const;

    // Преобразование текста в числа и обратно
    int charToNumber(QChar ch) const;
    QChar numberToChar(int num) const;
    QVector<uint64_t> textToNumbers(const QString& text) const;
    QString numbersToText(const QVector<uint64_t>& numbers) const;
};

// ==================== Регистратор ====================
class ElGamalSignCipherRegister
{
public:
    ElGamalSignCipherRegister();
};

#endif // ELGAMALSIGN_H
