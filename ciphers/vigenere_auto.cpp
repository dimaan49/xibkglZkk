#include "vigenere_auto.h"
#include <QStringBuilder>

VigenereAutoCipher::VigenereAutoCipher() {
    alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
}

int VigenereAutoCipher::getLetterIndex(QChar letter) const {
    return alphabet.indexOf(letter);
}

// Генерация ключа для шифрования: keyLetter + текст без последней буквы
QString VigenereAutoCipher::generateEncryptionKey(const QString& text, QChar keyLetter) const {
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);

    if (filteredText.isEmpty()) {
        return QString();
    }

    // Ключ = первая буква ключа + открытый текст без последней буквы
    return keyLetter + filteredText.left(filteredText.length() - 1);
}

// Генерация ключа для дешифрования
QString VigenereAutoCipher::generateDecryptionKey(const QString& text, QChar keyLetter) const {
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);

    if (filteredText.isEmpty()) {
        return QString();
    }

    // Для дешифрования ключ генерируется рекурсивно во время дешифрования
    // Возвращаем пустую строку, так как ключ будет строиться по ходу дешифрования
    return QString();
}

CipherResult VigenereAutoCipher::encrypt(const QString& text, QChar keyLetter) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);

    if (filteredText.isEmpty()) {
        return CipherResult(QString(), QVector<CipherStep>(), alphabet, name(), false);
    }

    // Генерируем ключ: keyLetter + текст без последней буквы
    QString key = generateEncryptionKey(text, keyLetter);
    QString result;

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        QChar keyChar = key[i];

        int textPos = getLetterIndex(ch);
        int keyPos = getLetterIndex(keyChar);

        // Шифрование: (текст + ключ) mod n
        int newPos = (textPos + keyPos) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        // Описание шага
        QString stepDesc;
        if (i == 0) {
            stepDesc = QStringLiteral(u"%1[%2] + %3[%4] = %5[%6] (ключевая буква)")
                .arg(ch).arg(textPos)
                .arg(keyChar).arg(keyPos)
                .arg(newChar).arg(newPos);
        } else {
            stepDesc = QStringLiteral(u"%1[%2] + %3[%4] = %5[%6] (буква %7 открытого текста)")
                .arg(ch).arg(textPos)
                .arg(keyChar).arg(keyPos)
                .arg(newChar).arg(newPos)
                .arg(filteredText[i-1]);
        }

        steps.append(CipherStep(i, ch, QString(newChar), stepDesc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

CipherResult VigenereAutoCipher::decrypt(const QString& text, QChar keyLetter) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);

    if (filteredText.isEmpty()) {
        return CipherResult(QString(), QVector<CipherStep>(), alphabet, name(), false);
    }

    QString result;

    // Дешифруем первую букву (используем только keyLetter)
    QChar firstCh = filteredText[0];
    int firstTextPos = getLetterIndex(firstCh);
    int firstKeyPos = getLetterIndex(keyLetter);

    int firstNewPos = (firstTextPos - firstKeyPos + n) % n;
    QChar firstNewChar = alphabet[firstNewPos];
    result.append(firstNewChar);

    QString firstDesc = QStringLiteral(u"%1[%2] - %3[%4] = %5[%6]")
        .arg(firstCh).arg(firstTextPos)
        .arg(keyLetter).arg(firstKeyPos)
        .arg(firstNewChar).arg(firstNewPos);

    steps.append(CipherStep(0, firstCh, QString(firstNewChar), firstDesc));

    // Дешифруем остальные буквы (используем предыдущие расшифрованные буквы как ключ)
    for (int i = 1; i < filteredText.length(); ++i) {
        // Ключевая буква = предыдущая буква открытого текста
        QChar keyChar = result[i-1];
        QChar ch = filteredText[i];

        int textPos = getLetterIndex(ch);
        int keyPos = getLetterIndex(keyChar);

        int newPos = (textPos - keyPos + n) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        QString desc = QStringLiteral(u"%1[%2] - %3[%4] = %5[%6] (ключ из предыдущей буквы открытого текста)")
            .arg(ch).arg(textPos)
            .arg(keyChar).arg(keyPos)
            .arg(newChar).arg(newPos);

        steps.append(CipherStep(i, ch, QString(newChar), desc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

QString VigenereAutoCipher::name() const {
    return QStringLiteral(u"Шифр Виженера с самоключом");
}

QString VigenereAutoCipher::description() const {
    return QStringLiteral(u"Автоключевой шифр: ключ = keyLetter + открытый_текст[0..n-2]");
}
