#include "magmasblock.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QBitArray>

MagmaSBlockCipher::MagmaSBlockCipher()
{
    initializeSBlocks();
}

void MagmaSBlockCipher::initializeSBlocks()
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

QString MagmaSBlockCipher::lettersToBinary(const QString& letters)
{
    QString binary;
    for (int i = 0; i < letters.length(); ++i) {
        QChar ch = letters[i];
        int index = m_alphabet.indexOf(ch);
        if (index >= 0) {
            binary.append(QString::number(index, 2).rightJustified(5, '0'));
        }
    }
    return binary;
}

QString MagmaSBlockCipher::binaryToLetters(const QString& binary)
{
    QString letters;
    for (int i = 0; i + 4 < binary.length(); i += 5) {
        QString bits = binary.mid(i, 5);
        bool ok;
        int index = bits.toInt(&ok, 2);
        if (ok && index >= 0 && index < m_alphabet.length()) {
            letters.append(m_alphabet[index]);
        } else {
            letters.append('?');
        }
    }
    return letters;
}

// Циклический сдвиг влево на n бит для 32-битной строки
QString MagmaSBlockCipher::rotateLeft32(const QString& bits32, int n)
{
    if (bits32.length() != 32) return bits32;

    n = n % 32;
    if (n == 0) return bits32;

    return bits32.mid(n) + bits32.left(n);
}

// Циклический сдвиг вправо на n бит для 32-битной строки
QString MagmaSBlockCipher::rotateRight32(const QString& bits32, int n)
{
    if (bits32.length() != 32) return bits32;

    n = n % 32;
    if (n == 0) return bits32;

    return bits32.right(n) + bits32.left(32 - n);
}

// Обработка 32-битного блока с S-заменами и сдвигом
QString MagmaSBlockCipher::process32BitBlock(const QString& block32, int startSBlockIndex, bool encrypt)
{
    if (block32.length() < 32) {
        return block32.leftJustified(32, '0');
    }

    QString result;

    if (encrypt) {
        // ШИФРОВАНИЕ: S-блоки, затем сдвиг
        int sBlockIndex = startSBlockIndex;

        // Применяем S-блоки
        for (int i = 0; i < 32; i += 4) {
            QString subBlock = block32.mid(i, 4);
            bool ok;
            int inputValue = subBlock.toInt(&ok, 2);

            if (ok) {
                int outputValue = m_sBlocks[sBlockIndex % 8][inputValue];
                result.append(QString::number(outputValue, 2).rightJustified(4, '0'));
            } else {
                result.append(subBlock);
            }
            sBlockIndex++;
        }

        // Сдвиг влево на 11 бит
        result = rotateLeft32(result, 11);

    } else {
        // ДЕШИФРОВАНИЕ: сначала отменяем сдвиг, потом обратные S-блоки

        // Отменяем сдвиг: сдвиг вправо на 11 бит
        QString afterShift = rotateRight32(block32, 11);

        int sBlockIndex = startSBlockIndex;

        // Применяем обратные S-блоки
        for (int i = 0; i < 32; i += 4) {
            QString subBlock = afterShift.mid(i, 4);
            bool ok;
            int inputValue = subBlock.toInt(&ok, 2);

            if (ok) {
                // Обратное преобразование
                int outputValue = -1;
                for (int j = 0; j < 16; ++j) {
                    if (m_sBlocks[sBlockIndex % 8][j] == inputValue) {
                        outputValue = j;
                        break;
                    }
                }
                if (outputValue == -1) {
                    outputValue = inputValue;
                }
                result.append(QString::number(outputValue, 2).rightJustified(4, '0'));
            } else {
                result.append(subBlock);
            }
            sBlockIndex++;
        }
    }

    return result;
}

// Обработка 64-битного блока
QString MagmaSBlockCipher::process64BitBlock(const QString& block64, int startSBlockIndex, bool encrypt)
{
    if (block64.length() < 64) {
        return block64.leftJustified(64, '0');
    }

    // Делим на два 32-битных блока
    QString left32 = block64.mid(0, 32);
    QString right32 = block64.mid(32, 32);

    // Обрабатываем ЛЕВУЮ часть
    QString processedLeft = process32BitBlock(left32, startSBlockIndex, encrypt);
    QString processedRight = process32BitBlock(right32, startSBlockIndex, encrypt);

    // Объединяем результаты
    return processedLeft + processedRight;
}

CipherResult MagmaSBlockCipher::encrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    // Преобразуем буквы в двоичный вид
    QString binaryText = lettersToBinary(filteredText);

    CipherStep step1;
    step1.index = 0;
    step1.originalChar = QChar('T');
    step1.resultValue = QString("%1 бит").arg(binaryText.length());
    step1.description = QString("Текст '%1' → %2 бит (%3 букв × 5 бит)")
                      .arg(filteredText)
                      .arg(binaryText.length())
                      .arg(filteredText.length());
    result.steps.append(step1);

    // Разбиваем на блоки по 64 бита с дополнением нулями
    QString encryptedBinary;
    int blockCounter = 0;

    for (int i = 0; i < binaryText.length(); i += 64) {
        QString block64bit = binaryText.mid(i, 64);
        blockCounter++;

        // Дополняем нулями до 64 бит, если нужно
        if (block64bit.length() < 64) {
            block64bit = block64bit.leftJustified(64, '0');
        }

        // Определяем начальный S-блок для этого блока
        int startSBlockIndex = 0;

        // Обрабатываем блок
        QString processedBlock = process64BitBlock(block64bit, startSBlockIndex, true);
        encryptedBinary.append(processedBlock);

        // Добавляем шаг для этого блока
        CipherStep blockStep;
        blockStep.index = blockCounter;
        blockStep.originalChar = QChar('0' + (blockCounter % 10));
        blockStep.resultValue = processedBlock.mid(0, 20) + "...";
        blockStep.description = QString("Блок %1: L и R части: S-блоки 1-8 → ROL 11")
                              .arg(blockCounter);
        result.steps.append(blockStep);
    }

    // Преобразуем двоичный результат обратно в буквы
    QString encryptedText = binaryToLetters(encryptedBinary);

    CipherStep finalStep;
    finalStep.index = 999;
    finalStep.originalChar = QChar('R');
    finalStep.resultValue = encryptedText;
    finalStep.description = QString("Зашифрованный текст: %1 букв")
                          .arg(encryptedText.length());
    result.steps.append(finalStep);

    result.result = encryptedText;
    return result;
}

CipherResult MagmaSBlockCipher::decrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    // Преобразуем зашифрованные буквы в двоичный вид
    QString binaryText = lettersToBinary(filteredText);

    CipherStep step1;
    step1.index = 0;
    step1.originalChar = QChar('T');
    step1.resultValue = QString("%1 бит").arg(binaryText.length());
    step1.description = QString("Зашифрованный текст '%1' → %2 бит")
                      .arg(filteredText)
                      .arg(binaryText.length());
    result.steps.append(step1);

    // Разбиваем на блоки по 64 бита и дешифруем
    QString decryptedBinary;
    int blockCounter = 0;

    for (int i = 0; i < binaryText.length(); i += 64) {
        QString block64bit = binaryText.mid(i, 64);
        blockCounter++;

        // Дополняем нулями до 64 бит, если нужно
        if (block64bit.length() < 64) {
            block64bit = block64bit.leftJustified(64, '0');
        }

        // Важно: используем ТОТ ЖЕ порядок S-блоков, что и при шифровании
        int startSBlockIndex = 0;

        // Обрабатываем блок (дешифрование)
        QString processedBlock = process64BitBlock(block64bit, startSBlockIndex, false);
        decryptedBinary.append(processedBlock);

        CipherStep blockStep;
        blockStep.index = blockCounter;
        blockStep.originalChar = QChar('0' + (blockCounter % 10));
        blockStep.resultValue = processedBlock.mid(0, 20) + "...";
        blockStep.description = QString("Блок %1: L и R части: S-блоки 1-8 → ROL 11")
                              .arg(blockCounter);
        result.steps.append(blockStep);
    }

    // Преобразуем двоичный результат обратно в буквы
    QString decryptedText = binaryToLetters(decryptedBinary);

    // Убираем padding (нулевые символы в конце)
    while (!decryptedText.isEmpty() && decryptedText.back() == m_alphabet[0]) {
        decryptedText.chop(1);
    }

    CipherStep finalStep;
    finalStep.index = 999;
    finalStep.originalChar = QChar('R');
    finalStep.resultValue = decryptedText;
    finalStep.description = QString("Расшифрованный текст: %1 букв")
                          .arg(decryptedText.length());
    result.steps.append(finalStep);

    result.result = decryptedText;
    return result;
}

MagmaSBlockCipherRegister::MagmaSBlockCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "magmasblock",
        "S-блок МАГМА",
        []() -> CipherInterface* { return new MagmaSBlockCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "magmasblock",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
        }
    );
}
