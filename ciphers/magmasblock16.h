#ifndef MAGMASBLOCK16_H
#define MAGMASBLOCK16_H

#include "cipherinterface.h"

class MagmaSBlock16Cipher : public CipherInterface
{
public:
    MagmaSBlock16Cipher();
    ~MagmaSBlock16Cipher() override = default;

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "МАГМА16 (HEX)"; }
    QString description() const override {
        return "Шифр на основе S-блоков ГОСТ 34.12-2015 (Магма) с HEX представлением. "
               "Входные данные: шестнадцатеричные символы (0-9, A-F). "
               "Текст разбивается на блоки по 8 hex-символов (32 бита), "
               "каждый символ заменяется по соответствующей таблице замены (π0-π7).";
    }

private:
    QString m_alphabet = QStringLiteral(u"0123456789ABCDEF");

    // Таблицы замены S-блоков (индексы 0-7 соответствуют таблицам 1-8)
    QVector<QVector<int>> m_sBlocks;

    // Вспомогательные методы
    void initializeSBlocks();
    QString process8HexBlock(const QString& block8, bool encrypt);
    int applySBlock(int sBlockIndex, int value);
    int applyInverseSBlock(int sBlockIndex, int value);
};

class MagmaSBlock16CipherRegister {
public:
    MagmaSBlock16CipherRegister();
};

static MagmaSBlock16CipherRegister magma16Register;

#endif // MAGMASBLOCK16_H
