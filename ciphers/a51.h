#ifndef A51_H
#define A51_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <bitset>
#include <cstdint>

// Класс шифра A5/1 (GSM)
class A51Cipher : public CipherInterface
{
public:
    A51Cipher();
    virtual ~A51Cipher() = default;

    // CipherInterface interface
    virtual QString name() const override { return "A5/1 (GSM)"; }
    virtual QString description() const override { return "Потоковый шифр A5/1 с тремя РСЛОС и управлением тактированием"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

private:
    // Длины регистров
    static const int R1_LEN = 19;
    static const int R2_LEN = 22;
    static const int R3_LEN = 23;

    // Биты синхронизации (индексы с 0)
    static const int R1_CLOCK_BIT = 8;   // 9-й бит (индекс 8)
    static const int R2_CLOCK_BIT = 10;  // 11-й бит (индекс 10)
    static const int R3_CLOCK_BIT = 10;  // 11-й бит (индекс 10)

    // Многочлены обратной связи (позиции для XOR)
    static const int R1_TAPS[4];
    static const int R2_TAPS[2];
    static const int R3_TAPS[4];

    // Регистры
    uint32_t m_r1;  // 19 бит (максимум 0x7FFFF)
    uint32_t m_r2;  // 22 бита (максимум 0x3FFFFF)
    uint32_t m_r3;  // 23 бита (максимум 0x7FFFFF)

    // Номер кадра (22 бита)
    uint32_t m_frameNumber;

    // Алфавит для текстового ключа
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

    // Вспомогательные функции
    bool textToBinaryKey(const QString& textKey, std::bitset<64>& key) const;
    QString binaryToText(const std::bitset<64>& bits) const;
    bool binaryStringToBitset(const QString& binaryStr, std::bitset<64>& key) const;
    QString bitsetToBinaryString(const std::bitset<64>& bits) const;
    // В заголовочном файле a51.h добавить:
    void reset();


    // Функции РСЛОС
    uint32_t feedbackR1() const;
    uint32_t feedbackR2() const;
    uint32_t feedbackR3() const;

    // Функция большинства (majority function)
    bool majority(bool x, bool y, bool z) const;

    // Получение бита синхронизации из регистра
    bool getClockBit(uint32_t reg, int bitPos) const;

    // Сдвиг регистра с обратной связью
    void shiftR1();
    void shiftR2();
    void shiftR3();

    // Инициализация регистров (64 + 22 + 100 тактов)
    void initializeRegisters(const std::bitset<64>& key, uint32_t frameNumber);

    // Генерация одного бита гаммы
    bool generateKeystreamBit();

    // Генерация гаммы заданной длины
    std::bitset<64> generateGamma(int length);

    // Шифрование/дешифрование текста
    CipherResult processText(const QString& text, const std::bitset<64>& key, bool encrypt);

    // Преобразование текста в биты (русский алфавит -> 5 бит)
    std::bitset<64> textToBits(const QString& text) const;

    // Преобразование битов в текст (5 бит -> русская буква)
    QString bitsToText(const std::bitset<64>& bits) const;

    // Преобразование строки битов в QByteArray
    QByteArray bitsToBytes(const std::bitset<64>& bits, int numBits) const;
};

// Класс для регистрации шифра
class A51CipherRegister
{
public:
    A51CipherRegister();
};

// Виджет для ввода бинарного ключа
class BinaryKeyEdit : public QLineEdit
{
    Q_OBJECT

public:
    BinaryKeyEdit(QWidget* parent = nullptr);
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

// Виджет для ввода текстового ключа
class TextKeyEdit : public QLineEdit
{
    Q_OBJECT

public:
    TextKeyEdit(QWidget* parent = nullptr);
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

#endif // A51_H
