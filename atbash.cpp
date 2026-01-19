#include "atbash.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

AtbashCipher::AtbashCipher()
{
}

CipherResult AtbashCipher::encrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    // Фильтруем только буквы алфавита
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    QString encryptedText;
    int n = m_alphabet.length();

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar originalChar = filteredText[i];
        int index = m_alphabet.indexOf(originalChar);

        if (index != -1) {
            int mirrorIndex = n - 1 - index;
            QChar resultChar = m_alphabet[mirrorIndex];
            encryptedText.append(resultChar);

            // Добавляем шаг для детализации
            CipherStep step;
            step.index = i;
            step.originalChar = originalChar;
            step.resultValue = resultChar;
            step.description = QString("%1 → %2 (зеркальное отражение)")
                              .arg(originalChar)
                              .arg(resultChar);
            result.steps.append(step);
        }
    }

    result.result = encryptedText;
    return result;
}

AtbashCipherRegister::AtbashCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "atbash",
        "Атбаш",
        []() -> CipherInterface* { return new AtbashCipher(); }
    );

    // Атбаш не имеет параметров, но регистрируем пустую функцию
    CipherWidgetFactory::instance().registerCipherWidgets(
        "atbash",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
            // Нет параметров
        }
    );
}
