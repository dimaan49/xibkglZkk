#ifndef TRITHEMIUS_H
#define TRITHEMIUS_H

#include "ciphercore.h"

class TrithemiusCipher {
private:
    QString alphabet;

public:
    TrithemiusCipher();

    // Шифрование Тритемия
    // startShift: начальный сдвиг (по умолчанию 0)
    // stepShift: шаг увеличения сдвига (по умолчанию 1)
    CipherResult encrypt(const QString& text, int startShift = 0, int stepShift = 1) const;

    // Дешифрование Тритемия
    CipherResult decrypt(const QString& text, int startShift = 0, int stepShift = 1) const;

    QString name() const;
    QString description() const;

private:
    // Вспомогательный метод для вычисления сдвига для позиции i
    int getShiftForPosition(int position, int startShift, int stepShift) const;

    // Нормализация сдвига
    int normalizeShift(int shift) const;
};

#endif // TRITHEMIUS_H
