#include "atbash.h"

AtbashCipher::AtbashCipher() {
    alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
}

CipherResult AtbashCipher::encrypt(const QString& text) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст (убираем пробелы)
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);
    QString result;

    for (int i = 0; i < filteredText.size(); ++i) {
        QChar ch = filteredText[i];
        int pos = alphabet.indexOf(ch);

        int newPos = n - 1 - pos;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        QString desc = QStringLiteral(u"%1[%2] → %3[%4]")
            .arg(ch).arg(pos).arg(newChar).arg(newPos);
        steps.append(CipherStep(i, ch, QString(newChar), desc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}


CipherResult AtbashCipher::decrypt(const QString& text) const {
    return encrypt(text);
}

QString AtbashCipher::name() const {
    return QStringLiteral(u"Атбаш");
}

QString AtbashCipher::description() const {
    return QStringLiteral(u"Зеркальный шифр: А↔Я, Б↔Ю, В↔Э, ...");
}
