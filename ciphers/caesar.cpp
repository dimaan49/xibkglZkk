#include "caesar.h"
#include <QStringBuilder>

CaesarCipher::CaesarCipher() {
    alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
}

// Нормализация сдвига (остаток от деления по модулю длины алфавита)
int CaesarCipher::normalizeShift(int shift) const {
    int n = alphabet.size();
    shift = shift % n;

    // Обеспечиваем положительный результат
    if (shift < 0) {
        shift += n;
    }

    return shift;
}

CipherResult CaesarCipher::encrypt(const QString& text, int shift) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();
    int normalizedShift = normalizeShift(shift);

    // Фильтруем текст (убираем пробелы)
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);
    QString result;

    for (int i = 0; i < filteredText.size(); ++i) {
        QChar ch = filteredText[i];
        int pos = alphabet.indexOf(ch);

        int newPos = (pos + normalizedShift) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        QString desc = QStringLiteral(u"%1[%2] + %3 = %4[%5]")
            .arg(ch).arg(pos)
            .arg(normalizedShift)
            .arg(newChar).arg(newPos);
        steps.append(CipherStep(i, ch, QString(newChar), desc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

CipherResult CaesarCipher::decrypt(const QString& text, int shift) const {
    // Дешифрование = шифрование с отрицательным сдвигом
    return encrypt(text, -shift);
}

QString CaesarCipher::name() const {
    return QStringLiteral(u"Шифр Цезаря");
}

QString CaesarCipher::description() const {
    return QStringLiteral(u"Шифр сдвига: каждая буква сдвигается на фиксированное число позиций");
}
