#include "belazo.h"
#include <QStringBuilder>

BelazoCipher::BelazoCipher() {
    alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
}

int BelazoCipher::getLetterIndex(QChar letter) const {
    return alphabet.indexOf(letter);
}

// Упрощенная генерация ключа (без пробелов)
QString BelazoCipher::generateKey(const QString& text, const QString& key) const {
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);
    QString filteredKey = CipherUtils::filterAlphabetOnly(key, alphabet);

    if (filteredKey.isEmpty()) {
        return QString(); // Пустой ключ
    }

    QString generatedKey;
    int keyLength = filteredKey.length();
    int textLength = filteredText.length();

    for (int i = 0; i < textLength; ++i) {
        generatedKey.append(filteredKey[i % keyLength]);
    }

    return generatedKey;
}

CipherResult BelazoCipher::encrypt(const QString& text, const QString& key) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст (убираем пробелы)
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);
    QString filteredKey = CipherUtils::filterAlphabetOnly(key, alphabet);

    if (filteredKey.isEmpty()) {
        // Возвращаем пустой результат если ключ пустой
        return CipherResult(QString(), QVector<CipherStep>(), alphabet, name(), false);
    }

    // Генерируем ключ нужной длины
    QString generatedKey = generateKey(text, key);
    QString result;

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        QChar keyChar = generatedKey[i];

        int textPos = getLetterIndex(ch);
        int keyPos = getLetterIndex(keyChar);

        // Шифрование: (текст + ключ) mod n
        int newPos = (textPos + keyPos) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        // Описание шага
        QString desc = QStringLiteral(u"%1[%2] + %3[%4] = %5[%6]")
            .arg(ch).arg(textPos)
            .arg(keyChar).arg(keyPos)
            .arg(newChar).arg(newPos);

        steps.append(CipherStep(i, ch, QString(newChar), desc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

CipherResult BelazoCipher::decrypt(const QString& text, const QString& key) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст (убираем пробелы)
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);
    QString filteredKey = CipherUtils::filterAlphabetOnly(key, alphabet);

    if (filteredKey.isEmpty()) {
        return CipherResult(QString(), QVector<CipherStep>(), alphabet, name(), false);
    }

    // Генерируем ключ нужной длины
    QString generatedKey = generateKey(text, key);
    QString result;

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        QChar keyChar = generatedKey[i];

        int textPos = getLetterIndex(ch);
        int keyPos = getLetterIndex(keyChar);

        // Дешифрование: (шифртекст - ключ + n) mod n
        int newPos = (textPos - keyPos + n) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        // Описание шага
        QString desc = QStringLiteral(u"%1[%2] - %3[%4] = %5[%6]")
            .arg(ch).arg(textPos)
            .arg(keyChar).arg(keyPos)
            .arg(newChar).arg(newPos);

        steps.append(CipherStep(i, ch, QString(newChar), desc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

QString BelazoCipher::name() const {
    return QStringLiteral(u"Шифр Белазо");
}

QString BelazoCipher::description() const {
    return QStringLiteral(u"Полиалфавитный шифр с ключевым словом");
}
