#ifndef CAESAR_H
#define CAESAR_H

#include "ciphercore.h"

class CaesarCipher {
private:
    QString alphabet;

public:
    CaesarCipher();

    // Шифрование с указанным сдвигом (по умолчанию +3)
    CipherResult encrypt(const QString& text, int shift = 3) const;

    // Дешифрование (отрицательный сдвиг)
    CipherResult decrypt(const QString& text, int shift = 3) const;

    QString name() const;
    QString description() const;

private:
    // Вспомогательный метод для нормализации сдвига
    int normalizeShift(int shift) const;
};

#endif // CAESAR_H
