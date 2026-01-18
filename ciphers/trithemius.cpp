#include "trithemius.h"
#include <QStringBuilder>

TrithemiusCipher::TrithemiusCipher() {
    alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
}

int TrithemiusCipher::normalizeShift(int shift) const {
    int n = alphabet.size();
    shift = shift % n;

    if (shift < 0) {
        shift += n;
    }

    return shift;
}

int TrithemiusCipher::getShiftForPosition(int position, int startShift, int stepShift) const {
    // Для позиции i: shift = startShift + stepShift * i
    return startShift + stepShift * position;
}

CipherResult TrithemiusCipher::encrypt(const QString& text, int startShift, int stepShift) const {
    QVector<CipherStep> steps;
    int n = alphabet.size();

    // Фильтруем текст (убираем пробелы)
    QString filteredText = CipherUtils::filterAlphabetOnly(text, alphabet);
    QString result;

    for (int i = 0; i < filteredText.size(); ++i) {
        QChar ch = filteredText[i];
        int pos = alphabet.indexOf(ch);

        int shift = startShift + stepShift * i;
        int normalizedShift = normalizeShift(shift);

        int newPos = (pos + normalizedShift) % n;
        QChar newChar = alphabet[newPos];
        result.append(newChar);

        QString desc = QStringLiteral(u"%1[%2] + (%3 + %4×%5) = %6[%7]")
            .arg(ch).arg(pos)
            .arg(startShift).arg(stepShift).arg(i)
            .arg(newChar).arg(newPos);

        steps.append(CipherStep(i, ch, QString(newChar), desc));
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

CipherResult TrithemiusCipher::decrypt(const QString& text, int startShift, int stepShift) const {
    QVector<CipherStep> steps;
    QString result;
    int n = alphabet.size();

    QString upperText = text.toUpper();
    int letterCounter = 0;

    for (int i = 0; i < upperText.size(); ++i) {
        QChar ch = upperText[i];
        int pos = alphabet.indexOf(ch);

        if (pos != -1) {
            // Вычисляем сдвиг для текущей позиции
            int shift = getShiftForPosition(letterCounter, startShift, stepShift);
            int normalizedShift = normalizeShift(shift);

            // Дешифрование: вычитаем сдвиг
            int newPos = (pos - normalizedShift + n) % n;
            QChar newChar = alphabet[newPos];
            result.append(newChar);

            // Формируем описание
            QString desc;
            if (stepShift == 0) {
                desc = QStringLiteral(u"%1[%2] - %3 → %4[%5]")
                    .arg(ch).arg(pos)
                    .arg(normalizedShift)
                    .arg(newChar).arg(newPos);
            } else {
                desc = QStringLiteral(u"%1[%2] - (%3 + %4×%5) → %6[%7]")
                    .arg(ch).arg(pos)
                    .arg(startShift).arg(stepShift).arg(letterCounter)
                    .arg(newChar).arg(newPos);
            }

            steps.append(CipherStep(i, ch, QString(newChar), desc));
            letterCounter++;

        } else {
            result.append(ch);
            steps.append(CipherStep(i, ch, QString(ch),
                QStringLiteral(u"Не в алфавите")));
        }
    }

    return CipherResult(result, steps, alphabet, name(), false);
}

QString TrithemiusCipher::name() const {
    return QStringLiteral(u"Шифр Тритемия");
}

QString TrithemiusCipher::description() const {
    return QStringLiteral(u"Полиалфавитный шифр с прогрессирующим сдвигом");
}
