#ifndef ECC_H
#define ECC_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include "classes/numberlineedit.h"
#include <QVector>
#include <QPair>
#include <cstdint>

class ECCCipher : public CipherInterface
{
public:
    ECCCipher();
    virtual ~ECCCipher() = default;

    QString name() const override { return "ECC (Эль-Гамаль)"; }
    QString description() const override { return "Асимметричный шифр на эллиптических кривых (схема Эль-Гамаля)"; }
    QString alphabet() const override { return m_alphabet; }
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    static bool validateParameters(uint64_t a, uint64_t b, uint64_t p,
                                   const ECC_Point& G, uint64_t cB,
                                   QString& errorMessage);

private:
    const QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;
};

class ECCPointEdit : public QWidget
{
    Q_OBJECT

public:
    ECCPointEdit(QWidget* parent = nullptr);
    ECC_Point getPoint() const;
    void setPoint(const ECC_Point& point);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }

private:
    NumberLineEdit* m_xEdit;
    NumberLineEdit* m_yEdit;
    bool m_valid = true;
};

class ECCCipherRegister
{
public:
    ECCCipherRegister();
};

#endif // ECC_H
