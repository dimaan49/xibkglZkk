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
        {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
        {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
        {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
        {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
        {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
        {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
        {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
        {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
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

QString MagmaSBlock16Cipher::process8HexBlock(const QString& block8, bool encrypt)
{
    QString result;

    for (int i = 0; i < block8.length(); ++i) {
        QChar ch = block8[i];
        int value = m_alphabet.indexOf(ch.toUpper());

        if (value == -1) {
            return QString();
        }

        int sBlockIndex = 7 - i;
        int outputValue = encrypt ? applySBlock(sBlockIndex, value)
                                  : applyInverseSBlock(sBlockIndex, value);
        result.append(m_alphabet[outputValue]);
    }

    return result;
}

CipherResult MagmaSBlock16Cipher::process(const QString& text, const QVariantMap& params, bool encrypt)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString direction = encrypt ? "Зашифрованный" : "Расшифрованный";
    QString sBlocksDesc = encrypt ? "S-блоки π7-π0" : "обратные S-блоки π7-π0";

    // Нормализуем HEX
    QString hexText = CoreHex::normalizeHex(text);

    if (hexText.isEmpty()) {
        result.result = "Нет hex-символов для преобразования";
        return result;
    }


    QString workingText = hexText;

    // убрать блок если нужно пройти ГОСТ проверку, т.к. хоть алгоритм раотает правильно, но при вводе hex из ГОСТ добавить 4 лишних символа и все словмается
    // === ПАДДИНГ (только при шифровании) ===
    if (encrypt) {
        QByteArray bytes = CoreHex::hexToBytes(hexText);
        QByteArray paddedBytes = CoreHex::pkcs7Pad(bytes, 4);
        workingText = CoreHex::bytesToHex(paddedBytes);

        CipherStep padStep;
        padStep.index = 0;
        padStep.originalChar = QChar('P');
        padStep.resultValue = workingText;
        padStep.description = QString("Паддинг PKCS#7: %1 → %2 (добавлено %3 байт)")
                             .arg(hexText)
                             .arg(workingText)
                             .arg(paddedBytes.size() - bytes.size());
        result.steps.append(padStep);
    } else {
        // Проверяем кратность 8 при расшифровании
        if (hexText.length() % 8 != 0) {
            result.result = QString("Ошибка: длина шифртекста (%1 символов) должна быть кратна 8")
                           .arg(hexText.length());
            return result;
        }
    }

    // Стартовый шаг
    CipherStep startStep;
    startStep.index = encrypt ? 1 : 0;
    startStep.originalChar = QChar('T');
    startStep.resultValue = QString("%1 hex-символов").arg(workingText.length());
    startStep.description = QString("%1 текст: %2").arg(direction).arg(workingText);
    result.steps.append(startStep);

    // Поблочная обработка (блок = 8 HEX-символов)
    QString output;
    int blockCounter = 0;

    for (int i = 0; i < workingText.length(); i += 8) {
        QString block8 = workingText.mid(i, 8);
        blockCounter++;

        QString processedBlock = process8HexBlock(block8, encrypt);
        output.append(processedBlock);

        CipherStep blockStep;
        blockStep.index = blockCounter;
        blockStep.originalChar = QChar('0' + (blockCounter % 10));
        blockStep.resultValue = processedBlock;
        blockStep.description = QString("Блок %1: %2 → %3 (%4)")
                              .arg(blockCounter).arg(block8).arg(processedBlock).arg(sBlocksDesc);
        result.steps.append(blockStep);
    }

    // === УДАЛЕНИЕ ПАДДИНГА (только при расшифровании) ===
    if (!encrypt) {
        QByteArray decryptedBytes = CoreHex::hexToBytes(output);
        QByteArray unpaddedBytes = CoreHex::pkcs7Unpad(decryptedBytes);
        output = CoreHex::bytesToHex(unpaddedBytes);

        CipherStep unpadStep;
        unpadStep.index = 998;
        unpadStep.originalChar = QChar('U');
        unpadStep.resultValue = output;
        unpadStep.description = QString("Удаление паддинга PKCS#7: %1 → %2 (удалено %3 байт)")
                               .arg(CoreHex::bytesToHex(decryptedBytes))
                               .arg(output)
                               .arg(decryptedBytes.size() - unpaddedBytes.size());
        result.steps.append(unpadStep);
    }

    // Финальный шаг
    CipherStep finalStep;
    finalStep.index = 999;
    finalStep.originalChar = QChar('R');
    finalStep.resultValue = output;
    finalStep.description = QString("%1 текст: %2").arg(direction).arg(output);
    result.steps.append(finalStep);

    result.result = output;
    return result;
}

CipherResult MagmaSBlock16Cipher::encrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, true);
}

CipherResult MagmaSBlock16Cipher::decrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, false);
}

MagmaSBlock16CipherRegister::MagmaSBlock16CipherRegister()
{
    CipherFactory::instance().registerCipher(
        8,
        "S-блок замены МАГМА",
        []() -> CipherInterface* { return new MagmaSBlock16Cipher(); },
        CipherCategory::Polyalphabetic
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        8,
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
        }
    );
}
