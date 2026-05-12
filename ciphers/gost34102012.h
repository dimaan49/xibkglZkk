#ifndef GOST34102012_H
#define GOST34102012_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

// Точка на эллиптической кривой (малые числа)
struct ECC_Point {
    uint64_t x;
    uint64_t y;
    bool isInfinity;

    ECC_Point() : x(0), y(0), isInfinity(true) {}
    ECC_Point(uint64_t x_, uint64_t y_) : x(x_), y(y_), isInfinity(false) {}

    bool operator==(const ECC_Point& other) const {
        if (isInfinity && other.isInfinity) return true;
        if (isInfinity != other.isInfinity) return false;
        return x == other.x && y == other.y;
    }

    QString toString() const {
        if (isInfinity) return "Infinity";
        return QString("(%1, %2)").arg(x).arg(y);
    }
};

class GOST34102012Cipher : public CipherInterface
{
public:
    GOST34102012Cipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "ГОСТ Р 34.10-2012 (ЭЦП на эллиптических кривых)"; }
    QString description() const override {
        return "ГОСТ Р 34.10-2012 — алгоритм электронной цифровой подписи "
               "на основе эллиптических кривых (малые числа).";
    }
    QString alphabet() const override { return m_alphabet; }

    bool isAvailable() const { return true; }

    // Статический метод для вычисления порядка кривой
    static void computeCurveOrder(uint64_t p, uint64_t a, uint64_t b,
                                  uint64_t& curveOrder, uint64_t& subgroupOrder, uint64_t& cofactor,
                                  QString& log);

private:
    const QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    // Арифметика эллиптической кривой (малые числа)
    ECC_Point pointDouble(const ECC_Point& P, uint64_t p, uint64_t a) const;
    ECC_Point pointAdd(const ECC_Point& P, const ECC_Point& Q, uint64_t p, uint64_t a) const;
    ECC_Point pointMul(uint64_t k, const ECC_Point& P, uint64_t p, uint64_t a) const;

    // Парсинг чисел
    uint64_t parseUint64(const QString& str) const;
};

// Регистратор
class GOST34102012CipherRegister
{
public:
    GOST34102012CipherRegister();
};

#endif // GOST34102012_H
