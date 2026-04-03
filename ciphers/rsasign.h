#ifndef RSASIGN_H
#define RSASIGN_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <array>
#include <cstdint>

// ==================== NumberLineEditSign ====================
class NumberLineEditSign : public QLineEdit
{
    Q_OBJECT
public:
    explicit NumberLineEditSign(QWidget* parent = nullptr);
    uint64_t getValue() const;
    void setValue(uint64_t value);
    void setValid(bool valid);

protected:
    void focusInEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    QString m_originalStyle;
};

// ==================== RSASignCipher ====================
class RSASignCipher : public CipherInterface
{
public:
    RSASignCipher();

    // Основные методы шифрования/расшифрования
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "RSA с цифровой подписью"; }
    QString description() const override {
        return "Алгоритм RSA с цифровой подписью. "
               "При шифровании создается подпись хеша сообщения, "
               "при расшифровании подпись проверяется.";
    }



    // Статические методы для генерации ключей
    static uint64_t generatePrimeStatic(int bits);
    static uint64_t generateEStatic(uint64_t phi);
    static bool isPrimeStatic(uint64_t n, int k = 10);
    static uint64_t modPowStatic(uint64_t base, uint64_t exp, uint64_t mod);
    static uint64_t gcdStatic(uint64_t a, uint64_t b);

    // Методы для работы с числами
    uint64_t modInverse(uint64_t e, uint64_t phi) const;
    uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) const;

    // Хеш-функция квадратичной свертки
    uint64_t computeHash(const QString& text, uint64_t p, QVector<CipherStep>& steps, int stepOffset) const;

private:
    const QString m_alphabet = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

    // Проверка параметров (с учетом p_hash)
    bool validateParameters(uint64_t p, uint64_t q, uint64_t e, uint64_t p_hash, QString& errorMessage) const;

    // Преобразование текста в числа и обратно
    int charToNumber(QChar ch) const;
    QChar numberToChar(int num) const;
    QVector<uint64_t> textToNumbers(const QString& text) const;
    QString numbersToText(const QVector<uint64_t>& numbers) const;

    // Основные криптографические операции
    uint64_t encryptNumber(uint64_t m, uint64_t e, uint64_t n) const;
    uint64_t decryptNumber(uint64_t c, uint64_t d, uint64_t n) const;

    // Вспомогательные методы
    bool isPrime(uint64_t n, int k = 10) const;
    uint64_t gcd(uint64_t a, uint64_t b) const;
};

// ==================== Регистратор ====================
class RSASignCipherRegister
{
public:
    RSASignCipherRegister();
};

#endif // RSASIGN_H
