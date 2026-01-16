#include "vigenere_ciphertext.h"
#include <QStringBuilder>

VigenereCiphertextCipher::VigenereCiphertextCipher() {
    alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
}

int VigenereCiphertextCipher::getLetterIndex(QChar letter) const {
    return alphabet.indexOf(letter);
}

CipherResult VigenereCiphertextCipher::encrypt(const QString& text, QChar keyLetter) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);

    if (filteredText.isEmpty()) {
        return CipherResult(QString(), QVector<CipherStep>(), alphabet, name(), false);
    }

    QString result;
    QChar currentKey = keyLetter; // Начинаем с заданной буквы ключа

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];

        int textPos = getLetterIndex(ch);
        int keyPos = getLetterIndex(currentKey);

        // Шифрование: (открытый текст + ключ) mod n
        int newPos = (textPos + keyPos) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        // Ключ для следующей буквы = текущий шифротекст
        currentKey = newChar;

        // Описание шага
        QString stepDesc;
        if (i == 0) {
            stepDesc = QStringLiteral(u"%1[%2] + %3[%4] = %5[%6] (начальный ключ)")
                .arg(ch).arg(textPos)
                .arg(keyLetter).arg(keyPos)
                .arg(newChar).arg(newPos);
        } else {
            stepDesc = QStringLiteral(u"%1[%2] + %3[%4] = %5[%6] (ключ из шифротекста)")
                .arg(ch).arg(textPos)
                .arg(result[i-1]).arg(getLetterIndex(result[i-1]))
                .arg(newChar).arg(newPos);
        }

        steps.append(CipherStep(i, ch, QString(newChar), stepDesc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

CipherResult VigenereCiphertextCipher::decrypt(const QString& text, QChar keyLetter) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);

    if (filteredText.isEmpty()) {
        return CipherResult(QString(), QVector<CipherStep>(), alphabet, name(), false);
    }

    QString result;
    QChar currentKey = keyLetter;

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];

        int textPos = getLetterIndex(ch);
        int keyPos = getLetterIndex(currentKey);

        // Дешифрование: (шифротекст - ключ + n) mod n
        int newPos = (textPos - keyPos + n) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        // Ключ для следующей буквы = текущий шифротекст
        currentKey = ch;

        // Описание шага
        QString stepDesc;
        if (i == 0) {
            stepDesc = QStringLiteral(u"%1[%2] - %3[%4] = %5[%6] (начальный ключ)")
                .arg(ch).arg(textPos)
                .arg(keyLetter).arg(keyPos)
                .arg(newChar).arg(newPos);
        } else {
            stepDesc = QStringLiteral(u"%1[%2] - %3[%4] = %5[%6] (ключ из шифротекста)")
                .arg(ch).arg(textPos)
                .arg(filteredText[i-1]).arg(getLetterIndex(filteredText[i-1]))
                .arg(newChar).arg(newPos);
        }

        steps.append(CipherStep(i, ch, QString(newChar), stepDesc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

QString VigenereCiphertextCipher::name() const {
    return QStringLiteral(u"Шифр Виженера с ключом-шифротекстом");
}

QString VigenereCiphertextCipher::description() const {
    return QStringLiteral(u"Автоключевой шифр: ключ[i] = шифротекст[i-1] (для i>0)");
}
