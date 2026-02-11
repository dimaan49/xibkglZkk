#include "belazo.h"
#include <QLabel>
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

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

    CipherWidgetFactory::instance().registerCipherWidgets(
        "belazo",
        // Один набор виджетов вместо двух
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            // Базовые параметры
            QHBoxLayout* keyLayout = new QHBoxLayout();
            QLabel* keyLabel = new QLabel("Ключ:");
            QLineEdit* keyLineEdit = new QLineEdit(parent);
            keyLineEdit->setText("КЛЮЧ");
            keyLineEdit->setObjectName("key");

            keyLayout->addWidget(keyLabel);
            keyLayout->addWidget(keyLineEdit);
            keyLayout->addStretch();
            layout->addLayout(keyLayout);

            widgets["key"] = keyLineEdit;

            // Расширенные параметры
            QLabel* advancedLabel = new QLabel("Расширенные настройки:");
            advancedLabel->setStyleSheet("font-weight: bold; margin-top: 10px;");
            layout->addWidget(advancedLabel);

            // Режим работы
            QHBoxLayout* modeLayout = new QHBoxLayout();
            QLabel* modeLabel = new QLabel("Режим:");
            QComboBox* modeCombo = new QComboBox(parent);
            modeCombo->addItem("Стандартный");
            modeCombo->addItem("С автоключом");
            modeCombo->setObjectName("mode");

            modeLayout->addWidget(modeLabel);
            modeLayout->addWidget(modeCombo);
            modeLayout->addStretch();
            layout->addLayout(modeLayout);

            // Размер блока
            QHBoxLayout* blockLayout = new QHBoxLayout();
            QLabel* blockLabel = new QLabel("Размер блока:");
            QSpinBox* blockSpin = new QSpinBox(parent);
            blockSpin->setRange(1, 100);
            blockSpin->setValue(5);
            blockSpin->setObjectName("blockSize");

            blockLayout->addWidget(blockLabel);
            blockLayout->addWidget(blockSpin);
            blockLayout->addStretch();
            layout->addLayout(blockLayout);

            widgets["mode"] = modeCombo;
            widgets["blockSize"] = blockSpin;
        }
    );
}
