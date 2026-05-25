#include "trithemius.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

TrithemiusCipher::TrithemiusCipher()
{
}

CipherResult TrithemiusCipher::encrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString encrypted;
    int n = m_alphabet.size();

    for (int i = 0; i < filteredText.size(); ++i) {
        QChar ch = filteredText[i];
        int pos = CipherUtils::charToIndex(ch, m_alphabet);

        // Сдвиг = номер позиции (0, 1, 2, ...)
        int shift = i;
        int newPos = (pos + shift) % n;
        QChar newChar = CipherUtils::indexToChar(newPos, m_alphabet);
        encrypted.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = QString("%1[%2] + %3 = %4[%5]")
                          .arg(ch).arg(pos)
                          .arg(shift)
                          .arg(newChar).arg(newPos);
        result.steps.append(step);
    }

    result.result = encrypted;
    return result;
}

CipherResult TrithemiusCipher::decrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString inputText = text;
    int n = m_alphabet.size();
    QString decrypted;

    for (int i = 0; i < inputText.size(); ++i) {
        QChar ch = inputText[i];
        int pos = CipherUtils::charToIndex(ch, m_alphabet);

        int shift = i;  // сдвиг равен позиции в тексте, а не в фильтрованном
        int newPos = (pos - shift) % n;

        // Приводим к положительному
        if (newPos < 0) newPos += n;

        QChar newChar = CipherUtils::indexToChar(newPos, m_alphabet);
        decrypted.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = QString("%1[%2] - %3 = %4[%5]")
                          .arg(ch).arg(pos)
                          .arg(shift)
                          .arg(newChar).arg(newPos);
        result.steps.append(step);
    }

    result.result = decrypted;
    return result;
}

TrithemiusCipherRegister::TrithemiusCipherRegister()
{
    CipherFactory::instance().registerCipher(
        4,
        "Шифр Тритемия",
        []() -> CipherInterface* { return new TrithemiusCipher(); },
        CipherCategory::Polyalphabetic
    );

    // Нет параметров, регистрируем пустой виджет
    CipherWidgetFactory::instance().registerCipherWidgets(
        4,
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {
            // Нет параметров
        }
    );
}
