#include "trithemius.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

TrithemiusCipher::TrithemiusCipher()
{
}

int TrithemiusCipher::normalizeShift(int shift) const {
    int n = m_alphabet.size();
    shift = shift % n;

    if (shift < 0) {
        shift += n;
    }

    return shift;
}

CipherResult TrithemiusCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    int startShift = params.value("startShift", 0).toInt();
    const int stepShift = 1; // Фиксированный шаг = 1

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString encrypted;
    int n = m_alphabet.size();

    for (int i = 0; i < filteredText.size(); ++i) {
        QChar ch = filteredText[i];
        int pos = m_alphabet.indexOf(ch);

        int shift = startShift + stepShift * i; // startShift + 1 * i
        int normalizedShift = normalizeShift(shift);

        int newPos = (pos + normalizedShift) % n;
        QChar newChar = m_alphabet[newPos];
        encrypted.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = QString("%1[%2] + (%3+%4) = %5[%6]")
                          .arg(ch).arg(pos)
                          .arg(startShift).arg(i)  // startShift + i
                          .arg(newChar).arg(newPos);
        result.steps.append(step);
    }

    result.result = encrypted;
    return result;
}

CipherResult TrithemiusCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    int n = m_alphabet.size();
    int startShift = params.value("startShift", 0).toInt() % n;
    const int stepShift = 1; // Фиксированный шаг = 1

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString decrypted;


    for (int i = 0; i < filteredText.size(); ++i) {
        QChar ch = filteredText[i];
        int pos = m_alphabet.indexOf(ch);

        int shift = startShift + stepShift * i; // startShift + 1 * i
        int normalizedShift = normalizeShift(shift);

        int newPos = (pos - normalizedShift + n) % n;
        QChar newChar = m_alphabet[newPos];
        decrypted.append(newChar);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = QString("%1[%2] - (%3+%4) = %5[%6]")
                          .arg(ch).arg(pos)
                          .arg(startShift).arg(i)  // startShift + i
                          .arg(newChar).arg(newPos);
        result.steps.append(step);
    }

    result.result = decrypted;
    return result;
}

TrithemiusCipherRegister::TrithemiusCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "trithemius",
        "Тритемий",
        []() -> CipherInterface* { return new TrithemiusCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "trithemius",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QHBoxLayout* startShiftLayout = new QHBoxLayout();
            QLabel* startShiftLabel = new QLabel("Начальный сдвиг:");
            QSpinBox* startShiftSpinBox = new QSpinBox(parent);
            startShiftSpinBox->setValue(0);
            startShiftSpinBox->setObjectName("startShift");
            startShiftSpinBox->setEnabled(false);
            startShiftSpinBox->setToolTip("Начальный сдвиг для первой буквы");

            startShiftLayout->addWidget(startShiftLabel);
            startShiftLayout->addWidget(startShiftSpinBox);
            startShiftLayout->addStretch();
            layout->addLayout(startShiftLayout);

            // Добавляем информацию о фиксированном шаге
            QLabel* infoLabel = new QLabel("Шаг увеличения сдвига всегда = 1");
            infoLabel->setStyleSheet("color: #666; font-style: italic;");
            layout->addWidget(infoLabel);

            widgets["startShift"] = startShiftSpinBox;
        }
    );
}
