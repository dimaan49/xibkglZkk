#include "polibiusquare.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

PolybiusSquareCipher::PolybiusSquareCipher()
{
    initializeMaps();
}

void PolybiusSquareCipher::initializeMaps()
{
    int rows = 6;
    int cols = 6;

    int index = 0;
    for (int row = 1; row <= rows; ++row) {
        for (int col = 1; col <= cols; ++col) {
            if (index < m_alphabet.length()) {
                QChar ch = m_alphabet[index];
                QString coords = QString("%1%2").arg(row).arg(col);
                m_charToCoords[ch] = coords;
                m_coordsToChar[coords] = ch;
                ++index;
            }
        }
    }
}

CipherResult PolybiusSquareCipher::encrypt(const QString& text, const QVariantMap& params)
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

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar originalChar = filteredText[i];

        if (m_charToCoords.contains(originalChar)) {
            QString coords = m_charToCoords[originalChar];
            encryptedText.append(coords);

            // Добавляем шаг для детализации
            CipherStep step;
            step.index = i;
            step.originalChar = originalChar;
            step.resultValue = coords;
            step.description = QString("Шифрование: %1 → %2")
                              .arg(originalChar)
                              .arg(coords);
            result.steps.append(step);
        }
    }

    result.result = encryptedText;
    return result;
}

CipherResult PolybiusSquareCipher::decrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    // Убираем все символы, кроме цифр (0-9)
    QString digitsOnly = CipherUtils::filterAlphabetOnly(text, "0123456");

    if (digitsOnly.length() < 2) {
        result.result = "Недостаточно цифр для расшифрования";
        return result;
    }

    QString decryptedText;
    decryptedText.reserve(digitsOnly.length() / 2);
    int stepIndex = 0;

    for (int i = 0; i + 1 < digitsOnly.length(); i += 2) {
        QString coords = digitsOnly.mid(i, 2);
        int row = coords[0].digitValue();
        int col = coords[1].digitValue();

        bool isValid = false;

        // Проверка: цифры в диапазоне 1-6
        if (row >= 1 && row <= 6 && col >= 1 && col <= 6) {
            // Если строка 6, то столбец не больше 2 (т.к. букв 32, последняя позиция 62)
            if (row == 6) {
                isValid = (col <= 2);
            } else {
                isValid = true;
            }
        }

        if (isValid && m_coordsToChar.contains(coords)) {
            QChar ch = m_coordsToChar[coords];
            decryptedText.append(ch);

            CipherStep step;
            step.index = stepIndex++;
            step.originalChar = coords[0];
            step.resultValue = ch;
            step.description = QString("расшифрование: %1 → %2").arg(coords).arg(ch);
            result.steps.append(step);
        } else {
            CipherStep step;
            step.index = stepIndex++;
            step.originalChar = coords[0];
            step.resultValue = QString();
            step.description = QString("Пропуск: '%1' невалидные координаты (row=%2, col=%3)")
                              .arg(coords).arg(row).arg(col);
            result.steps.append(step);
        }
    }

    result.result = decryptedText;
    return result;
}

PolybiusSquareCipherRegister::PolybiusSquareCipherRegister()
{
    CipherFactory::instance().registerCipher(
        3,
        "Квадрат Полибия",
        []() -> CipherInterface* { return new PolybiusSquareCipher(); },
        CipherCategory::Monoalphabetic
    );

    // Квадрат Полибия не имеет параметров
    CipherWidgetFactory::instance().registerCipherWidgets(
        3,
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
            // Нет параметров
        }
    );
}
