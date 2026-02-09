#include "matrixcipher.h"
#include <algorithm>
#include <cmath>
#include <QDebug>

MatrixCipher::MatrixCipher(const QVector<QVector<int>>& matrix)
    : keyMatrix(matrix), hasValidInverse(false) {

    // Проверяем, что матрица квадратная
    if (!MatrixUtils::isSquareMatrix(matrix)) {
        qWarning() << "Матрица должна быть квадратной!";
        blockSize = 0;
        return;
    }

    blockSize = matrix.size();
    calculateInverseMatrix();
}

void MatrixCipher::calculateInverseMatrix() {
    if (blockSize == 0) {
        hasValidInverse = false;
        return;
    }

    try {
        inverseMatrix = MatrixUtils::inverseMatrix(keyMatrix);
        hasValidInverse = true;
    } catch (const std::exception& e) {
        qWarning() << "Не удалось вычислить обратную матрицу:" << e.what();
        hasValidInverse = false;
    }
}

QVector<int> MatrixCipher::textToNumbers(const QString& text) const {
    static const QString alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    QVector<int> numbers;

    QString cleanText = CipherUtils::filterAlphabetOnly(text, alphabet);

    for (const QChar& ch : cleanText) {
        int index = alphabet.indexOf(ch);
        if (index >= 0) {
            numbers.append(index); // А=0, Б=1, ..., Я=31
        }
    }

    return numbers;
}

QString MatrixCipher::numbersToText(const QVector<int>& numbers) const {
    static const QString alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    QString text;

    for (int num : numbers) {
        if (num >= 0 && num < alphabet.size()) {
            text.append(alphabet[num]);
        } else {
            text.append('?'); // Некорректный номер
        }
    }

    return text;
}

QVector<QVector<int>> MatrixCipher::splitIntoBlocks(const QVector<int>& numbers) const {
    QVector<QVector<int>> blocks;

    for (int i = 0; i < numbers.size(); i += blockSize) {
        QVector<int> block;
        for (int j = 0; j < blockSize && (i + j) < numbers.size(); ++j) {
            block.append(numbers[i + j]);
        }

        // Дополняем блок до нужного размера (буквой А=0)
        while (block.size() < blockSize) {
            block.append(0);
        }

        blocks.append(block);
    }

    return blocks;
}

QVector<int> MatrixCipher::combineBlocks(const QVector<QVector<int>>& blocks) const {
    QVector<int> result;

    for (const auto& block : blocks) {
        for (int num : block) {
            result.append(num);
        }
    }

    return result;
}

QString MatrixCipher::formatNumber(int num) const {
    // Форматируем число с ведущими пробелами до 3 знаков
    return MatrixUtils::numberToString(num, 3);
}

CipherResult MatrixCipher::encrypt(const QString& text) {
    QVector<CipherStep> steps;

    // Шаг 1: Проверка ключа
    if (blockSize == 0 || !hasValidInverse) {
        steps.append(CipherStep(1, QChar(),
            QStringLiteral(u"Ошибка: некорректная ключевая матрица"),
            QStringLiteral(u"Проверка ключа")));

        return CipherResult(QString(), steps,
                           QStringLiteral(u"Матричный шифр (ошибка)"),
                           name(), true); // isNumeric = true
    }

    steps.append(CipherStep(1, QChar(),
        QString("Ключевая матрица %1×%1").arg(blockSize),
        QStringLiteral(u"Проверка ключа")));

    // Шаг 2: Преобразование текста в числа
    QVector<int> numbers = textToNumbers(text);
    QString numbersStr = MatrixUtils::vectorToString(numbers);

    steps.append(CipherStep(2, QChar(), numbersStr,
        QString("Текст преобразован в числа (%1 символов)").arg(numbers.size())));

    // Шаг 3: Разбиение на блоки
    QVector<QVector<int>> blocks = splitIntoBlocks(numbers);
    steps.append(CipherStep(3, QChar(),
        QString("%1 блоков по %2 элемента").arg(blocks.size()).arg(blockSize),
        QStringLiteral(u"Разбиение на блоки")));

    // Шаг 4: Шифрование каждого блока
    QVector<QVector<int>> encryptedBlocks;
    int stepCounter = 4;

    for (int blockIdx = 0; blockIdx < blocks.size(); ++blockIdx) {
        const auto& block = blocks[blockIdx];
        QString blockStr = MatrixUtils::vectorToString(block);

        steps.append(CipherStep(stepCounter++, QChar(), blockStr,
            QString("Блок %1 (вектор)").arg(blockIdx + 1)));

        // Умножение матрицы на вектор
        QVector<int> encryptedBlock = MatrixUtils::multiplyMatrixVector(keyMatrix, block);
        encryptedBlocks.append(encryptedBlock);

        QString encryptedStr = MatrixUtils::vectorToString(encryptedBlock);
        steps.append(CipherStep(stepCounter++, QChar(), encryptedStr,
            QString("Блок %1 после умножения на матрицу").arg(blockIdx + 1)));
    }

    // Шаг 5: Объединение блоков
    QVector<int> encryptedNumbers = combineBlocks(encryptedBlocks);
    QString resultStr = MatrixUtils::vectorToString(encryptedNumbers);

    steps.append(CipherStep(stepCounter, QChar(), resultStr,
        QStringLiteral(u"Объединение зашифрованных блоков")));

    // Формируем описание
    QString description = QStringLiteral(u"Матричный шифр\n")
                        + QStringLiteral(u"Размер блока: %1\n").arg(blockSize)
                        + QStringLiteral(u"Ключевая матрица:\n")
                        + MatrixUtils::matrixToString(keyMatrix);

    if (hasValidInverse) {
        description += QStringLiteral(u"\nОбратная матрица существует\n");
    } else {
        description += QStringLiteral(u"\nОбратная матрица не существует\n");
    }

    return CipherResult(resultStr, steps, description, name(), true);
}

CipherResult MatrixCipher::decrypt(const QString& text) {
    QVector<CipherStep> steps;

    // Шаг 1: Проверка ключа
    if (blockSize == 0 || !hasValidInverse) {
        steps.append(CipherStep(1, QChar(),
            QStringLiteral(u"Ошибка: некорректная ключевая матрица или нет обратной"),
            QStringLiteral(u"Проверка ключа")));

        return CipherResult(QString(), steps,
                           QStringLiteral(u"Матричный шифр (дешифрование, ошибка)"),
                           name() + QStringLiteral(u" (дешифрование)"), true);
    }

    steps.append(CipherStep(1, QChar(),
        QString("Используется обратная матрица %1×%1").arg(blockSize),
        QStringLiteral(u"Проверка ключа")));

    // Шаг 2: Парсинг входных чисел
    QStringList numberStrs = text.split(" ", Qt::SkipEmptyParts);
    QVector<int> numbers;

    for (const QString& numStr : numberStrs) {
        bool ok;
        int num = numStr.toInt(&ok);
        if (ok) {
            numbers.append(num);
        }
    }

    // Проверяем, что количество чисел кратно размеру блока
    if (numbers.size() % blockSize != 0) {
        steps.append(CipherStep(2, QChar(),
            QStringLiteral(u"Ошибка: количество чисел (%1) не кратно размеру блока (%2)")
                .arg(numbers.size()).arg(blockSize),
            QStringLiteral(u"Парсинг чисел")));

        return CipherResult(QString(), steps,
                           QStringLiteral(u"Матричный шифр (дешифрование, ошибка)"),
                           name() + QStringLiteral(u" (дешифрование)"), true);
    }

    QString numbersStr = MatrixUtils::vectorToString(numbers);
    steps.append(CipherStep(2, QChar(), numbersStr,
        QString("Входные числа (%1 чисел)").arg(numbers.size())));

    // Шаг 3: Разбиение на блоки
    QVector<QVector<int>> blocks = splitIntoBlocks(numbers);
    steps.append(CipherStep(3, QChar(),
        QString("%1 блоков по %2 элемента").arg(blocks.size()).arg(blockSize),
        QStringLiteral(u"Разбиение на блоки")));

    // Шаг 4: Дешифрование каждого блока
    QVector<QVector<int>> decryptedBlocks;
    int stepCounter = 4;

    for (int blockIdx = 0; blockIdx < blocks.size(); ++blockIdx) {
        const auto& block = blocks[blockIdx];
        QString blockStr = MatrixUtils::vectorToString(block);

        steps.append(CipherStep(stepCounter++, QChar(), blockStr,
            QString("Блок %1 (вектор)").arg(blockIdx + 1)));

        // Умножение на обратную матрицу
        QVector<int> decryptedBlock = MatrixUtils::multiplyMatrixVector(inverseMatrix, block);
        decryptedBlocks.append(decryptedBlock);

        QString decryptedStr = MatrixUtils::vectorToString(decryptedBlock);
        steps.append(CipherStep(stepCounter++, QChar(), decryptedStr,
            QString("Блок %1 после умножения на обратную матрицу").arg(blockIdx + 1)));
    }

    // Шаг 5: Объединение блоков и преобразование в текст
    QVector<int> decryptedNumbers = combineBlocks(decryptedBlocks);

    // Убираем дополнение (нули в конце)
    while (!decryptedNumbers.isEmpty() && decryptedNumbers.last() == 0) {
        decryptedNumbers.removeLast();
    }

    QString decryptedText = numbersToText(decryptedNumbers);

    steps.append(CipherStep(stepCounter, QChar(), decryptedText,
        QStringLiteral(u"Преобразование чисел в текст")));

    // Формируем описание
    QString description = QStringLiteral(u"Дешифрование матричного шифра\n")
                        + QStringLiteral(u"Размер блока: %1\n").arg(blockSize)
                        + QStringLiteral(u"Используется обратная матрица:\n")
                        + MatrixUtils::matrixToString(inverseMatrix);

    return CipherResult(decryptedText, steps, description,
                       name() + QStringLiteral(u" (дешифрование)"), false);
}

QString MatrixCipher::getKeyMatrixString() const {
    return MatrixUtils::matrixToString(keyMatrix);
}

QString MatrixCipher::getInverseMatrixString() const {
    if (!hasValidInverse) {
        return QStringLiteral(u"Обратная матрица не существует");
    }
    return MatrixUtils::matrixToString(inverseMatrix);
}

bool MatrixCipher::hasValidKey() const {
    return blockSize > 0 && hasValidInverse;
}

QString MatrixCipher::name() const {
    return QStringLiteral(u"Матричный шифр");
}

QString MatrixCipher::description() const {
    return QStringLiteral(u"Шифрование с использованием матричного умножения");
}
