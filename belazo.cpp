#include "belazo.h"
#include "cipherfactory.h"

BelazoCipher::BelazoCipher()
{
}

QString BelazoCipher::generateKey(const QString& text, const QString& key) const
{
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);
    QString filteredKey = CipherUtils::filterAlphabetOnly(key, m_alphabet);

    if (filteredKey.isEmpty()) return QString();

    QString generatedKey;
    for (int i = 0; i < filteredText.length(); ++i) {
        generatedKey.append(filteredKey[i % filteredKey.length()]);
    }
    return generatedKey;
}

CipherResult BelazoCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString key = params.value("key", "КЛЮЧ").toString();
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);
    QString filteredKey = CipherUtils::filterAlphabetOnly(key, m_alphabet);

    if (filteredKey.isEmpty()) {
        result.result = "Ключ не содержит букв алфавита";
        return result;
    }

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString generatedKey = generateKey(text, key);
    QString transformed;
    int n = m_alphabet.size();

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        QChar keyChar = generatedKey[i];

        int textPos = m_alphabet.indexOf(ch);
        int keyPos = m_alphabet.indexOf(keyChar);
        int newPos = (textPos + keyPos) % n;
        QChar newChar = m_alphabet[newPos];
        transformed.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = QString("%1[%2] + %3[%4] = %5[%6]")
                          .arg(ch).arg(textPos)
                          .arg(keyChar).arg(keyPos)
                          .arg(newChar).arg(newPos);
        result.steps.append(step);
    }

    result.result = transformed;
    return result;
}

CipherResult BelazoCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString key = params.value("key", "КЛЮЧ").toString();
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);
    QString filteredKey = CipherUtils::filterAlphabetOnly(key, m_alphabet);

    if (filteredKey.isEmpty()) {
        result.result = "Ключ не содержит букв алфавита";
        return result;
    }

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString generatedKey = generateKey(text, key);
    QString transformed;
    int n = m_alphabet.size();

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        QChar keyChar = generatedKey[i];

        int textPos = m_alphabet.indexOf(ch);
        int keyPos = m_alphabet.indexOf(keyChar);
        int newPos = (textPos - keyPos + n) % n;
        QChar newChar = m_alphabet[newPos];
        transformed.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = QString("%1[%2] - %3[%4] = %5[%6]")
                          .arg(ch).arg(textPos)
                          .arg(keyChar).arg(keyPos)
                          .arg(newChar).arg(newPos);
        result.steps.append(step);
    }

    result.result = transformed;
    return result;
}

BelazoCipherRegister::BelazoCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "belazo",
        "Белазо",
        []() -> CipherInterface* { return new BelazoCipher(); }
    );
}
