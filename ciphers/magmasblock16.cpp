#include "magmasblock16.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"

MagmaSBlock16Cipher::MagmaSBlock16Cipher()
{
    initializeSBlocks();
}

void MagmaSBlock16Cipher::initializeSBlocks()
{
    m_sBlocks = {
        {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},  // π0'
        {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15}, // π1'
        {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0}, // π2'
        {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11}, // π3'
        {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12}, // π4'
        {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0}, // π5'
        {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7}, // π6'
        {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}  // π7'
    };
}

int MagmaSBlock16Cipher::applySBlock(int sBlockIndex, int value)
{
    if (sBlockIndex >= 0 && sBlockIndex < 8 && value >= 0 && value < 16) {
        return m_sBlocks[sBlockIndex][value];
    }
    return value;
}

int MagmaSBlock16Cipher::applyInverseSBlock(int sBlockIndex, int value)
{
    if (sBlockIndex >= 0 && sBlockIndex < 8) {
        for (int j = 0; j < 16; ++j) {
            if (m_sBlocks[sBlockIndex][j] == value) {
                return j;
            }
        }
    }
    return value;
}

// Обработка 8-hex символов блока (32 бита)
QString MagmaSBlock16Cipher::process8HexBlock(const QString& block8, bool encrypt)
{
    QString result;

    if (encrypt) {
        // ШИФРОВАНИЕ: применяем S-блоки в обратном порядке
        // a = a7||a6||a5||a4||a3||a2||a1||a0 ∈ V32, ai ∈ V4
        // t(a) = t(a7||…||a0) = π7(a7)||π6(a6)||π5(a5)||π4(a4)||π3(a3)||π2(a2)||π1(a1)||π0(a0)
        for (int i = 0; i < block8.length(); ++i) {
            QChar ch = block8[i];
            int value = m_alphabet.indexOf(ch.toUpper());

            if (value >= 0) {
                int sBlockIndex = 7 - i;
                int outputValue = applySBlock(sBlockIndex, value);
                result.append(m_alphabet[outputValue]);
            } else {
                result.append(ch);
            }
        }
    } else {
        // ДЕШИФРОВАНИЕ: применяем обратные S-блоки в том же порядке
        for (int i = 0; i < block8.length(); ++i) {
            QChar ch = block8[i];
            int value = m_alphabet.indexOf(ch.toUpper());

            if (value >= 0) {
                int sBlockIndex = 7 - i;
                int outputValue = applyInverseSBlock(sBlockIndex, value);
                result.append(m_alphabet[outputValue]);
            } else {
                result.append(ch);
            }
        }
    }

    return result;
}

CipherResult MagmaSBlock16Cipher::encrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    // Фильтруем только hex-символы и приводим к верхнему регистру
    QString filteredText = CipherUtils::filterAlphabetOnly(text.toUpper(), m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет hex-символов для преобразования";
        return result;
    }

    // Проверяем, что длина кратна 8 (32 бита)
    if (filteredText.length() % 8 != 0) {
        result.result = QString("Ошибка: длина текста (%1 символов) должна быть кратна 8 (для 32-битных блоков)")
                       .arg(filteredText.length());
        return result;
    }

    CipherStep step1;
    step1.index = 0;
    step1.originalChar = QChar('T');
    step1.resultValue = QString("%1 hex-символов").arg(filteredText.length());
    step1.description = QString("Исходный текст: %1").arg(filteredText);
    result.steps.append(step1);

    // Разбиваем на блоки по 8 hex-символов (32 бита)
    QString encrypted;
    int blockCounter = 0;

    for (int i = 0; i < filteredText.length(); i += 8) {
        QString block8 = filteredText.mid(i, 8);
        blockCounter++;

        // Обрабатываем блок
        QString processedBlock = process8HexBlock(block8, true);
        encrypted.append(processedBlock);

        // Добавляем шаг для этого блока
        CipherStep blockStep;
        blockStep.index = blockCounter;
        blockStep.originalChar = QChar('0' + (blockCounter % 10));
        blockStep.resultValue = processedBlock;
        blockStep.description = QString("Блок %1: %2 → %3 (S-блоки π7-π0)")
                              .arg(blockCounter).arg(block8).arg(processedBlock);
        result.steps.append(blockStep);
    }

    CipherStep finalStep;
    finalStep.index = 999;
    finalStep.originalChar = QChar('R');
    finalStep.resultValue = encrypted;
    finalStep.description = QString("Зашифрованный текст: %1").arg(encrypted);
    result.steps.append(finalStep);

    result.result = encrypted;
    return result;
}

CipherResult MagmaSBlock16Cipher::decrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    // Фильтруем только hex-символы и приводим к верхнему регистру
    QString filteredText = CipherUtils::filterAlphabetOnly(text.toUpper(), m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет hex-символов для преобразования";
        return result;
    }

    // Проверяем, что длина кратна 8 (32 бита)
    if (filteredText.length() % 8 != 0) {
        result.result = QString("Ошибка: длина текста (%1 символов) должна быть кратна 8 (для 32-битных блоков)")
                       .arg(filteredText.length());
        return result;
    }

    CipherStep step1;
    step1.index = 0;
    step1.originalChar = QChar('T');
    step1.resultValue = QString("%1 hex-символов").arg(filteredText.length());
    step1.description = QString("Зашифрованный текст: %1").arg(filteredText);
    result.steps.append(step1);

    // Разбиваем на блоки по 8 hex-символов (32 бита)
    QString decrypted;
    int blockCounter = 0;

    for (int i = 0; i < filteredText.length(); i += 8) {
        QString block8 = filteredText.mid(i, 8);
        blockCounter++;

        // Обрабатываем блок (дешифрование)
        QString processedBlock = process8HexBlock(block8, false);
        decrypted.append(processedBlock);

        CipherStep blockStep;
        blockStep.index = blockCounter;
        blockStep.originalChar = QChar('0' + (blockCounter % 10));
        blockStep.resultValue = processedBlock;
        blockStep.description = QString("Блок %1: %2 → %3 (обратные S-блоки π7-π0)")
                              .arg(blockCounter).arg(block8).arg(processedBlock);
        result.steps.append(blockStep);
    }

    CipherStep finalStep;
    finalStep.index = 999;
    finalStep.originalChar = QChar('R');
    finalStep.resultValue = decrypted;
    finalStep.description = QString("Расшифрованный текст: %1").arg(decrypted);
    result.steps.append(finalStep);

    result.result = decrypted;
    return result;
}

MagmaSBlock16CipherRegister::MagmaSBlock16CipherRegister()
{
    CipherFactory::instance().registerCipher(
        "magma16",
        "МАГМА16 (HEX)",
        []() -> CipherInterface* { return new MagmaSBlock16Cipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "magma16",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
        }
    );
}
