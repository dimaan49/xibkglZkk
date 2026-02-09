#include "vigenere_ciphertext.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

VigenereCiphertextCipher::VigenereCiphertextCipher()
{
}

CipherResult VigenereCiphertextCipher::encrypt(const QString& text, const QVariantMap& params)
{
    QChar keyLetter = params.value("keyLetter", "А").toChar();
    return process(text, keyLetter, true);
}

CipherResult VigenereCiphertextCipher::decrypt(const QString& text, const QVariantMap& params)
{
    QChar keyLetter = params.value("keyLetter", "А").toChar();
    return process(text, keyLetter, false);
}

CipherResult VigenereCiphertextCipher::process(const QString& text, QChar keyLetter, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    // Фильтруем только буквы алфавита
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString transformed;
    int n = m_alphabet.size();
    QChar currentKey = keyLetter;

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        int textPos = m_alphabet.indexOf(ch);
        int keyPos = m_alphabet.indexOf(currentKey);

        if (keyPos == -1) {
            // Запасной ключ
            keyPos = 0;
        }

        int newPos;
        QString operation;

        if (encrypt) {
            newPos = (textPos + keyPos) % n;
            operation = "+";
        } else {
            newPos = (textPos - keyPos + n) % n;
            operation = "-";
        }

        QChar newChar = m_alphabet[newPos];
        transformed.append(newChar);

        // Обновляем ключ
        currentKey = encrypt ? newChar : ch;

        // Формируем описание
        QString stepDesc;
        if (i == 0) {
            stepDesc = QString("%1[%2] %3 %4[%5] = %6[%7] (начальный ключ)")
                .arg(ch).arg(textPos)
                .arg(operation)
                .arg(keyLetter).arg(keyPos)
                .arg(newChar).arg(newPos);
        } else {
            QChar prevChar = encrypt ? transformed[i-1] : filteredText[i-1];
            stepDesc = QString("%1[%2] %3 %4[%5] = %6[%7] (ключ из шифротекста)")
                .arg(ch).arg(textPos)
                .arg(operation)
                .arg(prevChar).arg(m_alphabet.indexOf(prevChar))
                .arg(newChar).arg(newPos);
        }

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = stepDesc;
        result.steps.append(step);
    }

    result.result = transformed;
    return result;
}

VigenereCiphertextCipherRegister::VigenereCiphertextCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "vigenere_ciphertext",
        "Виженер (шифротекст)",
        []() -> CipherInterface* { return new VigenereCiphertextCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "vigenere_ciphertext",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QHBoxLayout* keyLayout = new QHBoxLayout();
            QLabel* keyLabel = new QLabel("Начальная буква ключа:");
            QLineEdit* keyLineEdit = new QLineEdit(parent);
            keyLineEdit->setText("А");
            keyLineEdit->setMaxLength(1);
            keyLineEdit->setMaximumWidth(50);
            keyLineEdit->setObjectName("keyLetter");
            keyLineEdit->setToolTip("Первая буква ключа (обычно 'А' или 'Ю')");

            QLabel* infoLabel = new QLabel("Каждая следующая буква ключа = предыдущий шифротекст");
            infoLabel->setStyleSheet("color: #666; font-style: italic;");

            keyLayout->addWidget(keyLabel);
            keyLayout->addWidget(keyLineEdit);
            keyLayout->addStretch();
            layout->addLayout(keyLayout);
            layout->addWidget(infoLabel);

            widgets["keyLetter"] = keyLineEdit;
        }
    );
}
