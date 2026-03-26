#ifndef ELGAMAL_H
#define ELGAMAL_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <QPair>
#include <QTextEdit>
#include <QLineEdit>
#include <cstdint>

// Класс шифра ElGamal
class ElGamalCipher : public CipherInterface
{
public:
    ElGamalCipher();
    virtual ~ElGamalCipher() = default;

    // CipherInterface interface
    virtual QString name() const override { return "ElGamal"; }
    virtual QString description() const override { return "Асимметричный шифр ElGamal на основе дискретного логарифмирования"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

private:
    // Алфавит для преобразования текста в числа
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

    // Вспомогательные математические функции
    bool isPrime(uint64_t n, int k = 5) const;
    uint64_t gcd(uint64_t a, uint64_t b) const;
    uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) const;
    uint64_t modInverse(uint64_t a, uint64_t mod) const;
    bool isPrimitiveRoot(uint64_t g, uint64_t p) const;

    // Проверка параметров
    bool validateParameters(uint64_t p, uint64_t g, uint64_t x, QString& errorMessage) const;
    bool validateMessageNumber(uint64_t m, uint64_t p, QString& errorMessage) const;

    // Генерация случайных чисел
    uint64_t generatePrime(int bits = 16) const;
    uint64_t generatePrimitiveRoot(uint64_t p) const;
    uint64_t generateRandomK(uint64_t p) const;

    // Преобразование текста в числа (каждая буква -> число 1-32)
    QVector<uint64_t> textToNumbers(const QString& text) const;
    QString numbersToText(const QVector<uint64_t>& numbers) const;

    // Основные операции ElGamal
    QPair<uint64_t, uint64_t> encryptNumber(uint64_t m, uint64_t p, uint64_t g, uint64_t y, uint64_t k) const;
    uint64_t decryptNumber(uint64_t a, uint64_t b, uint64_t p, uint64_t x) const;

    // Алфавит в число и обратно
    int charToNumber(QChar ch) const;
    QChar numberToChar(int num) const;

    // Статические методы для генерации
public:
    static uint64_t generatePrimeStatic(int bits = 16);
    static uint64_t generatePrimitiveRootStatic(uint64_t p);
    static uint64_t generateRandomKStatic(uint64_t p);
    static bool isPrimeStatic(uint64_t n, int k = 5);
    static uint64_t modPowStatic(uint64_t base, uint64_t exp, uint64_t mod);
};

// Виджет для ввода чисел
class ElGamalNumberEdit : public QLineEdit
{
    Q_OBJECT

public:
    explicit ElGamalNumberEdit(QWidget* parent = nullptr);
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

// Виджет для ввода рандомизаторов
class RandomizersEdit : public QTextEdit
{
    Q_OBJECT

public:
    explicit RandomizersEdit(QWidget* parent = nullptr);
    QVector<uint64_t> getRandomizers() const;
    void setRandomizers(const QVector<uint64_t>& randomizers);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }

protected:
    void focusInEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    QString m_originalStyle;
};

// Класс для регистрации шифра
class ElGamalCipherRegister
{
public:
    ElGamalCipherRegister();
};

#endif // ELGAMAL_H
