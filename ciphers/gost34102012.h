#ifndef GOST34102012_H
#define GOST34102012_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

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

    // Статический метод для вычисления порядка кривой (использует CoreCurves)
    static void computeCurveOrder(uint64_t p, uint64_t a, uint64_t b,
                                  uint64_t& curveOrder, uint64_t& subgroupOrder, uint64_t& cofactor,
                                  QString& log);

private:
    const QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    uint64_t parseUint64(const QString& str) const;
};

class GOST34102012CipherRegister
{
public:
    GOST34102012CipherRegister();
};

#endif // GOST34102012_H
