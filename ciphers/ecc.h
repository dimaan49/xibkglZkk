#ifndef ECC_H
#define ECC_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <QPair>
#include <cstdint>

// Структура точки на эллиптической кривой
struct ECPoint {
    uint64_t x;
    uint64_t y;
    bool isInfinity;  // бесконечно удаленная точка (нейтральный элемент)

    ECPoint() : x(0), y(0), isInfinity(true) {}
    ECPoint(uint64_t x_, uint64_t y_) : x(x_), y(y_), isInfinity(false) {}

    bool operator==(const ECPoint& other) const {
        if (isInfinity && other.isInfinity) return true;
        if (isInfinity || other.isInfinity) return false;
        return x == other.x && y == other.y;
    }

    bool operator!=(const ECPoint& other) const {
        return !(*this == other);
    }
};

// Класс шифра ECC (Эль-Гамаль на эллиптических кривых)
class ECCCipher : public CipherInterface
{
public:
    ECCCipher();
    virtual ~ECCCipher() = default;

    virtual QString name() const override { return "ECC (Эль-Гамаль)"; }
    virtual QString description() const override { return "Асимметричный шифр на эллиптических кривых (схема Эль-Гамаля)"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    // Статические методы для арифметики на кривой
    static ECPoint pointAdd(const ECPoint& P, const ECPoint& Q, uint64_t a, uint64_t p);
    static ECPoint pointDouble(const ECPoint& P, uint64_t a, uint64_t p);
    static ECPoint pointMultiply(const ECPoint& P, uint64_t k, uint64_t a, uint64_t p);
    static bool isPointOnCurve(const ECPoint& P, uint64_t a, uint64_t b, uint64_t p);

    // Статическая проверка параметров
    static bool validateParameters(uint64_t a, uint64_t b, uint64_t p,
                                   const ECPoint& G, uint64_t cB,
                                   QString& errorMessage);

private:
    // Вспомогательные математические функции
    static uint64_t modAdd(uint64_t a, uint64_t b, uint64_t p);
    static uint64_t modSub(uint64_t a, uint64_t b, uint64_t p);
    static uint64_t modMul(uint64_t a, uint64_t b, uint64_t p);
    static uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod);
    static uint64_t modInverse(uint64_t a, uint64_t p);

    // Преобразование числа в строку
    static QString pointToString(const ECPoint& P);
    static ECPoint stringToPoint(const QString& str);
};

// Виджет для ввода чисел
class ECCNumberEdit : public QLineEdit
{
    Q_OBJECT

public:
    ECCNumberEdit(QWidget* parent = nullptr);
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

// Виджет для ввода точки (x,y)
class ECCPointEdit : public QWidget
{
    Q_OBJECT

public:
    ECCPointEdit(QWidget* parent = nullptr);
    ECPoint getPoint() const;
    void setPoint(const ECPoint& point);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }

private:
    ECCNumberEdit* m_xEdit;
    ECCNumberEdit* m_yEdit;
    bool m_valid = true;
};

// Класс для регистрации шифра
class ECCCipherRegister
{
public:
    ECCCipherRegister();
};

#endif // ECC_H
