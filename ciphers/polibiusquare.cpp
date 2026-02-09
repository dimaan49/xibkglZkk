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

    // Для дешифрования используем исходный текст без фильтрации
    // Потому что нам нужны цифры из текста

    QString decryptedText;
    QString filteredText;
    filteredText = CipherUtils::filterAlphabetOnly(text, m_numeric);
    int i = 0;

    while (i < filteredText.length()) {
        // Берем по две цифры за раз (координаты)
        if (i + 1 < text.length()) {
            QString twoDigits = filteredText.mid(i, 2);

            // Проверяем, что это две цифры
            bool isTwoDigits = true;
            for (int j = 0; j < 2; ++j) {
                if (!twoDigits[j].isDigit()) {
                    isTwoDigits = false;
                    break;
                }
            }
            QString decryptedChar;
            if (isTwoDigits && m_coordsToChar.contains(twoDigits)) {
                if ( twoDigits[1] > "2" && twoDigits[0] == "6") {
                    decryptedChar = "";
                    decryptedText.append(decryptedChar);
                } else {
                    decryptedChar = m_coordsToChar[twoDigits];
                    decryptedText.append(decryptedChar);
                }

                // Добавляем шаг для детализации
                CipherStep step;
                step.index = i / 2;  // Индекс в расшифрованном тексте
                step.originalChar = twoDigits[0];  // Первая цифра координаты
                step.resultValue = decryptedChar;
                step.description = QString("Дешифрование: %1 → %2")
                                  .arg(twoDigits)
                                  .arg(decryptedChar);
                result.steps.append(step);

                i += 2;
                continue;
            }
        }

        // Если не удалось расшифровать, оставляем символ как есть
        QChar skippedChar = filteredText[i];
        //decryptedText.append(skippedChar);

        // Добавляем шаг для пропущенного символа
        CipherStep step;
        step.index = i;
        step.originalChar = skippedChar;
        step.resultValue = skippedChar;
        step.description = QString("Пропуск: символ '%1' не является валидными координатами")
                          .arg(skippedChar);
        result.steps.append(step);

        i += 1;
    }

    result.result = decryptedText;
    return result;
}

PolybiusSquareCipherRegister::PolybiusSquareCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "polybius",
        "Квадрат Полибия",
        []() -> CipherInterface* { return new PolybiusSquareCipher(); }
    );

    // Квадрат Полибия не имеет параметров
    CipherWidgetFactory::instance().registerCipherWidgets(
        "polybius",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
            // Нет параметров
        }
    );
}
