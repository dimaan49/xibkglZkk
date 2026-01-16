#ifndef BELAZO_H
#define BELAZO_H

#include "ciphercore.h"

class BelazoCipher {
private:
    QString alphabet;

public:
    BelazoCipher();

    // Шифрование Белазо с ключевым словом
    CipherResult encrypt(const QString& text, const QString& key) const;

    // Дешифрование Белазо с ключевым словом
    CipherResult decrypt(const QString& text, const QString& key) const;

    QString name() const;
    QString description() const;

private:
    // Генерация повторяющегося ключа
    QString generateKey(const QString& text, const QString& key) const;

    // Нормализация сдвига
    int normalizeShift(int shift) const;

    // Получение индекса буквы
    int getLetterIndex(QChar letter) const;
};

#endif // BELAZO_H
