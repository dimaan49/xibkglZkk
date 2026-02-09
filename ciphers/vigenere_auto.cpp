#include "vigenere_auto.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

VigenereAutoCipher::VigenereAutoCipher()
{
}

QString VigenereAutoCipher::generateEncryptionKey(const QString& text, QChar keyLetter) const
{
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        return QString();
    }

    // Ключ = первая буква ключа + открытый текст без последней буквы
    return keyLetter + filteredText.left(filteredText.length() - 1);
}

CipherResult VigenereAutoCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QChar keyLetter = params.value("keyLetter", "А").toChar();
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    // Генерируем ключ: keyLetter + текст без последней буквы
    QString key = generateEncryptionKey(text, keyLetter);
    QString encrypted;
    int n = m_alphabet.size();

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        QChar keyChar = key[i];

        int textPos = m_alphabet.indexOf(ch);
        int keyPos = m_alphabet.indexOf(keyChar);

        int newPos = (textPos + keyPos) % n;
        QChar newChar = m_alphabet[newPos];
        encrypted.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);

        if (i == 0) {
            step.description = QString("%1[%2] + %3[%4] = %5[%6] (начальная буква ключа)")
                              .arg(ch).arg(textPos)
                              .arg(keyChar).arg(keyPos)
                              .arg(newChar).arg(newPos);
        } else {
            step.description = QString("%1[%2] + %3[%4] = %5[%6] (ключ из предыдущей буквы текста)")
                              .arg(ch).arg(textPos)
                              .arg(keyChar).arg(keyPos)
                              .arg(newChar).arg(newPos);
        }

        result.steps.append(step);
    }

    result.result = encrypted;
    return result;
}

CipherResult VigenereAutoCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QChar keyLetter = params.value("keyLetter", "А").toChar();
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString decrypted;
    int n = m_alphabet.size();

    // Первая буква: используем только keyLetter
    QChar firstCh = filteredText[0];
    int firstTextPos = m_alphabet.indexOf(firstCh);
    int firstKeyPos = m_alphabet.indexOf(keyLetter);

    int firstNewPos = (firstTextPos - firstKeyPos + n) % n;
    QChar firstNewChar = m_alphabet[firstNewPos];
    decrypted.append(firstNewChar);

    CipherStep firstStep;
    firstStep.index = 0;
    firstStep.originalChar = firstCh;
    firstStep.resultValue = QString(firstNewChar);
    firstStep.description = QString("%1[%2] - %3[%4] = %5[%6] (начальная буква ключа)")
                          .arg(firstCh).arg(firstTextPos)
                          .arg(keyLetter).arg(firstKeyPos)
                          .arg(firstNewChar).arg(firstNewPos);
    result.steps.append(firstStep);

    // Остальные буквы: используем предыдущие расшифрованные буквы как ключ
    for (int i = 1; i < filteredText.length(); ++i) {
        QChar keyChar = decrypted[i-1]; // Предыдущая расшифрованная буква
        QChar ch = filteredText[i];

        int textPos = m_alphabet.indexOf(ch);
        int keyPos = m_alphabet.indexOf(keyChar);

        int newPos = (textPos - keyPos + n) % n;
        QChar newChar = m_alphabet[newPos];
        decrypted.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = QString("%1[%2] - %3[%4] = %5[%6] (ключ из предыдущей расшифрованной буквы)")
                          .arg(ch).arg(textPos)
                          .arg(keyChar).arg(keyPos)
                          .arg(newChar).arg(newPos);
        result.steps.append(step);
    }

    result.result = decrypted;
    return result;
}

VigenereAutoCipherRegister::VigenereAutoCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "vigenere_auto",
        "Виженер (самоключ)",
        []() -> CipherInterface* { return new VigenereAutoCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "vigenere_auto",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QHBoxLayout* keyLayout = new QHBoxLayout();
            QLabel* keyLabel = new QLabel("Начальная буква ключа:");
            QLineEdit* keyLineEdit = new QLineEdit(parent);
            keyLineEdit->setText("А");
            keyLineEdit->setMaxLength(1);
            keyLineEdit->setMaximumWidth(50);
            keyLineEdit->setObjectName("keyLetter");
            keyLineEdit->setToolTip("Первая буква ключа (остальные берутся из открытого текста)");

            keyLayout->addWidget(keyLabel);
            keyLayout->addWidget(keyLineEdit);
            keyLayout->addStretch();
            layout->addLayout(keyLayout);

            QLabel* infoLabel = new QLabel("Ключ = начальная буква + открытый текст (без последней буквы)");
            infoLabel->setStyleSheet("color: #666; font-style: italic;");
            layout->addWidget(infoLabel);

            widgets["keyLetter"] = keyLineEdit;
        }
    );
}
