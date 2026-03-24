#ifndef RSA_H
#define RSA_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <QPair>
#include <vector>
#include <cstdint>
#include <QRegularExpression>

// Класс шифра RSA
class RSACipher : public CipherInterface
{
public:
    RSACipher();
    virtual ~RSACipher() = default;

    // CipherInterface interface
    virtual QString name() const override { return "RSA"; }
    virtual QString description() const override { return "Асимметричный шифр RSA (Rivest-Shamir-Adleman)"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    // Статические методы для генерации ключей (доступны извне)
    static uint64_t generatePrimeStatic(int bits = 16);
    static uint64_t generateEStatic(uint64_t phi);
    uint64_t generatePrime(int bits = 16) const;
    uint64_t generateE(uint64_t phi) const;
    static bool isPrimeStatic(uint64_t n, int k = 5);

private:
    // Алфавит для преобразования текста в числа
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

    // Вспомогательные математические функции
    bool isPrime(uint64_t n, int k = 5) const;
    uint64_t gcd(uint64_t a, uint64_t b) const;
    uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) const;
    uint64_t modInverse(uint64_t e, uint64_t phi) const;

    // Проверка параметров RSA
    bool validateParameters(uint64_t p, uint64_t q, uint64_t e, QString& errorMessage) const;

    // Преобразование текста в число (для блочного шифрования)
    QVector<uint64_t> textToNumbers(const QString& text) const;
    QString numbersToText(const QVector<uint64_t>& numbers) const;

    // Основные операции RSA
    uint64_t encryptNumber(uint64_t m, uint64_t e, uint64_t n) const;
    uint64_t decryptNumber(uint64_t c, uint64_t d, uint64_t n) const;

    // Алфавит в число и обратно
    int charToNumber(QChar ch) const;
    QChar numberToChar(int num) const;
};

// Класс для регистрации шифра
class RSACipherRegister
{
public:
    RSACipherRegister();
};

// Виджет для ввода чисел с проверкой
class NumberLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    NumberLineEdit(QWidget* parent = nullptr);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }
    uint64_t getValue() const;
    void setValue(uint64_t value);

protected:
    void focusInEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    QString m_originalStyle;
};

#endif // RSA_H
