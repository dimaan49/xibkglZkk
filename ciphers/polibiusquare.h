#ifndef POLYBIUSSQUARE_H
#define POLYBIUSSQUARE_H

#include "cipherinterface.h"

class PolybiusSquareCipher : public CipherInterface
{
public:
    PolybiusSquareCipher();
    ~PolybiusSquareCipher() override = default;

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "Квадрат Полибия"; }
    QString description() const override {
        return "Каждая буква заменяется на свои координаты в таблице 6×6. Координаты записываются слитно (например, А=11).";
    }

private:
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    QString m_numeric = QStringLiteral(u"0123456");
    QMap<QChar, QString> m_charToCoords;  // Буква → координаты
    QMap<QString, QChar> m_coordsToChar;  // Координаты → буква
    void initializeMaps();
};

class PolybiusSquareCipherRegister {
public:
    PolybiusSquareCipherRegister();
};

static PolybiusSquareCipherRegister polybiusRegister;

#endif // POLYBIUSSQUARE_H
