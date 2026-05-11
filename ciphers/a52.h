#ifndef A52_H
#define A52_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <bitset>
#include <cstdint>

// Класс шифра A5/2 (GSM)
class A52Cipher : public CipherInterface
{
public:
    A52Cipher();
    virtual ~A52Cipher() = default;

    // CipherInterface interface
    QString name() const override { return "A5/2 (GSM)"; }
    QString description() const override { return "Потоковый шифр A5/2 с четырьмя РСЛОС и управлением тактированием через R4"; }
    QString alphabet() const override {return m_alphabet; }
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

private:
    // Длины регистров
    static const int R1_LEN = 19;
    static const int R2_LEN = 22;
    static const int R3_LEN = 23;
    static const int R4_LEN = 17;  // Дополнительный регистр для A5/2

    // Биты синхронизации для R4 (управление тактированием)
    static const int R4_CLOCK_BIT1 = 3;   // для R2
    static const int R4_CLOCK_BIT2 = 7;   // для R3
    static const int R4_CLOCK_BIT3 = 10;  // для R1

    // Биты для мажоритарной функции F* (выходной бит)
    static const int R1_F_BITS[3];
    static const int R2_F_BITS[3];
    static const int R3_F_BITS[3];

    // Многочлены обратной связи
    static const int R1_TAPS[4];
    static const int R2_TAPS[2];
    static const int R3_TAPS[4];
    static const int R4_TAPS[2];  // x^17 + x^12 + 1

    // Регистры
    uint32_t m_r1;  // 19 бит
    uint32_t m_r2;  // 22 бита
    uint32_t m_r3;  // 23 бита
    uint32_t m_r4;  // 17 бит

    // Номер кадра (22 бита)
    uint32_t m_frameNumber;

    // Алфавит для текстового ключа
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

    // Вспомогательные функции
    bool textToBinaryKey(const QString& textKey, std::bitset<64>& key) const;
    QString binaryToText(const std::bitset<64>& bits) const;

    // Функции обратной связи
    uint32_t feedbackR1() const;
    uint32_t feedbackR2() const;
    uint32_t feedbackR3() const;
    uint32_t feedbackR4() const;

    // Функция большинства (majority function)
    bool majority(bool x, bool y, bool z) const;
    bool majorityFromBits(uint32_t reg, int bit1, int bit2, int bit3) const;

    // Получение бита из регистра
    bool getBit(uint32_t reg, int bitPos) const;

    // Сдвиг регистра с обратной связью
    void shiftR1();
    void shiftR2();
    void shiftR3();
    void shiftR4();

    // Инициализация регистров (64 + 22 + 1 + 99 тактов)
    void initializeRegisters(const std::bitset<64>& key, uint32_t frameNumber);

    // Генерация одного бита гаммы (с учетом F*)
    bool generateKeystreamBit();

    // Генерация гаммы заданной длины
    std::bitset<1024> generateGamma(int numBits);

    // Шифрование/дешифрование текста
    CipherResult processText(const QString& text, const std::bitset<64>& key, bool encrypt);

    // Преобразование текста в биты (русский алфавит -> 5 бит)
    std::bitset<1024> textToBits(const QString& text, int& totalBits) const;

    // Преобразование битов в текст (5 бит -> русская буква)
    QString bitsToText(const std::bitset<1024>& bits, int totalBits) const;
};

// Виджет для ввода бинарного ключа (A5/2)
class A52BinaryKeyEdit : public QLineEdit
{
    Q_OBJECT

public:
    A52BinaryKeyEdit(QWidget* parent = nullptr);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }
    std::bitset<64> getKey() const;
    void setKey(const std::bitset<64>& key);

protected:
    void focusInEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    QString m_originalStyle;
};

// Виджет для ввода текстового ключа (A5/2)
class A52TextKeyEdit : public QLineEdit
{
    Q_OBJECT

public:
    A52TextKeyEdit(QWidget* parent = nullptr);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }
    QString getTextKey() const;
    void setTextKey(const QString& key);
    void setAlphabet(const QString& alphabet);

protected:
    void focusInEvent(QFocusEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    QString m_originalStyle;
    QString m_alphabet;
};

// Класс для регистрации шифра
class A52CipherRegister
{
public:
    A52CipherRegister();
};

#endif // A52_H
