#include "caesar.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

CaesarCipher::CaesarCipher()
{
}

int CaesarCipher::getShift(const QVariantMap& params) const
{
    if (params.contains("shift")) {
        return params["shift"].toInt();
    }
    return 3; // значение по умолчанию
}

CipherResult CaesarCipher::encrypt(const QString& text, const QVariantMap& params)
{
    return shiftText(text, getShift(params), "шифрование");
}

CipherResult CaesarCipher::decrypt(const QString& text, const QVariantMap& params)
{
    return shiftText(text, -getShift(params), "дешифрование");
}

CipherResult CaesarCipher::shiftText(const QString& text, int shift, const QString& operation)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filtered.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString transformed;
    int n = m_alphabet.length();

    // Нормализуем сдвиг (делаем положительным)
    shift = (shift % n);

    for (int i = 0; i < filtered.length(); ++i) {
        QChar ch = filtered[i];
        int idx = m_alphabet.indexOf(ch);

        if (idx != -1) {
            int newIdx = (idx + shift) % n;
            QChar newChar = m_alphabet[newIdx];
            transformed.append(newChar);

            CipherStep step;
            step.index = i;
            step.originalChar = ch;
            step.resultValue = QString(newChar);
            step.description = QString("%1: %2 → %3 (сдвиг %4)")
                              .arg(operation)
                              .arg(ch)
                              .arg(newChar)
                              .arg(shift > 0 ? "+" + QString::number(shift) : QString::number(shift));
            result.steps.append(step);
        }
    }

    result.result = transformed;
    return result;
}

CaesarCipherRegister::CaesarCipherRegister()
{
    // Регистрируем шифр в фабрике
    CipherFactory::instance().registerCipher(
        "caesar",
        "Шифр Цезаря",
        []() -> CipherInterface* { return new CaesarCipher(); }
    );

    // Регистрируем виджеты параметров
    CipherWidgetFactory::instance().registerCipherWidgets(
        "caesar",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QHBoxLayout* shiftLayout = new QHBoxLayout();
            QLabel* shiftLabel = new QLabel("Сдвиг:");
            QSpinBox* shiftSpinBox = new QSpinBox(parent);
            shiftSpinBox->setValue(3);
            shiftSpinBox->setObjectName("shift");

            shiftLayout->addWidget(shiftLabel);
            shiftLayout->addWidget(shiftSpinBox);
            shiftLayout->addStretch();
            layout->addLayout(shiftLayout);

            widgets["shift"] = shiftSpinBox;
        }
    );
}
