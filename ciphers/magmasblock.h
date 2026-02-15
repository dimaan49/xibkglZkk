#ifndef MAGMASBLOCK_H
#define MAGMASBLOCK_H

/*
  ГОСТ Р 34.13-2015 -- правила дополнения сообщения
 4.1.1 Процедура 1 -- дополнение нулями (будем использовать это)!!!!!!!!!!!
 4.1.2 Процедура 2 -- дополнение одной единицей и нулями
 4.1.3 Процедура 3  -- не используем (ссылается на второй пункт если блок не выровнен)

 */

#include "cipherinterface.h"

class MagmaSBlockCipher : public CipherInterface
{
public:
    MagmaSBlockCipher();
    ~MagmaSBlockCipher() override = default;

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "S-блок МАГМА"; }
    QString description() const override {
        return "Шифр на основе S-блоков ГОСТ 34.12-2015 (Магма). "
               "Текст разбивается на блоки по 64 бита, каждый блок на две части по 32 бита, "
               "которые разбиваются на 8 подблоков по 4 бита и заменяются по таблицам замены.";
    }

private:
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

    // Таблицы замены S-блоков (индексы 0-7 соответствуют таблицам 1-8)
    QVector<QVector<int>> m_sBlocks;

    // Вспомогательные методы
    void initializeSBlocks();
    QString rotateLeft32(const QString& bits32, int n);
    QString rotateRight32(const QString& bits32, int n);
    QString lettersToBinary(const QString& letters);
    QString binaryToLetters(const QString& binary);
    QString process64BitBlock(const QString& block64, int startSBlockIndex, bool encrypt);
    QString process32BitBlock(const QString& block32, int startSBlockIndex, bool encrypt);
};

class MagmaSBlockCipherRegister {
public:
    MagmaSBlockCipherRegister();
};

static MagmaSBlockCipherRegister magmaRegister;

#endif // MAGMASBLOCK_H
