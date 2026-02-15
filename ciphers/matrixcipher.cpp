#include "matrixcipher.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "stylemanager.h"
#include <QDebug>
#include <QRegularExpression>
#include <cmath>
#include <algorithm>
#include <QLabel>
#include <QSpinBox>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QHeaderView>
#include <QMessageBox>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QFrame>

const QString MatrixCipher::ALPHABET = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

MatrixCipher::MatrixCipher() {}

CipherResult MatrixCipher::encrypt(const QString& text, const QVariantMap& params)
{
    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования", "Инициализация"));

    try {
        // Шаг 1: Получение и проверка матрицы
        if (!params.contains("matrix")) {
            steps.append(CipherStep(1, QChar(), "Ошибка: матрица не задана", "Проверка параметров"));
            return CipherResult("", steps, "Матричный шифр (ошибка)", name(), true);
        }

        QString matrixStr = params["matrix"].toString();
        QVector<QVector<int>> matrix;

        if (!parseMatrix(matrixStr, matrix)) {
            steps.append(CipherStep(1, QChar(), "Ошибка: некорректный формат матрицы", "Парсинг матрицы"));
            return CipherResult("", steps, "Матричный шифр (ошибка)", name(), true);
        }

        int size = matrix.size();

        // Форматируем матрицу для вывода
        QString matrixDisplay;
        for (int i = 0; i < size; i++) {
            matrixDisplay += "[";
            for (int j = 0; j < size; j++) {
                matrixDisplay += QString::number(matrix[i][j]);
                if (j < size - 1) matrixDisplay += " ";
            }
            matrixDisplay += "]\n";
        }

        steps.append(CipherStep(1, QChar(),
            QString("Ключевая матрица %1x%1:\n%2").arg(size).arg(matrixDisplay),
            "Загрузка матрицы"));

        // Шаг 2: Проверка обратимости и вычисление определителя
        int det;
        if (!isInvertible(matrix, det)) {
            steps.append(CipherStep(2, QChar(),
                QString("Ошибка: матрица необратима (det = %1)").arg(det),
                "Проверка обратимости"));
            return CipherResult("", steps, "Матричный шифр (ошибка)", name(), true);
        }

        steps.append(CipherStep(2, QChar(),
            QString("Определитель матрицы: det = %1").arg(det),
            "Вычисление определителя"));

        // Шаг 3: Вычисление обратной матрицы
        QVector<QVector<double>> inverseMatrix;
        if (!calculateInverse(matrix, inverseMatrix, det)) {
            steps.append(CipherStep(3, QChar(), "Ошибка: не удалось вычислить обратную матрицу", "Вычисление обратной матрицы"));
            return CipherResult("", steps, "Матричный шифр (ошибка)", name(), true);
        }

        // Форматируем обратную матрицу для вывода
        QString inverseDisplay;
        for (int i = 0; i < size; i++) {
            inverseDisplay += "[";
            for (int j = 0; j < size; j++) {
                // Форматируем с 3 знаками после запятой
                inverseDisplay += QString::number(inverseMatrix[i][j], 'f', 3);
                if (j < size - 1) inverseDisplay += " ";
            }
            inverseDisplay += "]\n";
        }

        steps.append(CipherStep(3, QChar(),
            QString("Обратная матрица %1x%1 (вычислена для дешифрования):\n%2").arg(size).arg(inverseDisplay),
            "Вычисление обратной матрицы"));

        // Шаг 4: Преобразование текста в числа
        QString cleanText = CipherUtils::filterAlphabetOnly(text, ALPHABET);
        if (cleanText.isEmpty()) {
            steps.append(CipherStep(4, QChar(), "Ошибка: текст не содержит букв алфавита", "Преобразование текста"));
            return CipherResult("", steps, "Матричный шифр (ошибка)", name(), true);
        }

        QVector<int> numbers = textToNumbers(cleanText);
        QString numbersStr;
        for (int i = 0; i < numbers.size(); i++) {
            numbersStr += QString::number(numbers[i] + 1); // +1 т.к. А=1 в выводе
            if (i < numbers.size() - 1) numbersStr += " ";
        }

        steps.append(CipherStep(4, QChar(),
            QString("Текст → числа (%1 чисел): %2").arg(numbers.size()).arg(numbersStr),
            "Преобразование текста"));

        // Шаг 5: Дополнение до кратного размеру блока
        int remainder = numbers.size() % size;
        int paddingCount = (remainder == 0) ? 0 : (size - remainder);

        for (int i = 0; i < paddingCount; i++) {
            numbers.append(0); // А=0
        }

        if (paddingCount > 0) {
            steps.append(CipherStep(5, QChar(),
                QString("Добавлено %1 нулей (буква А) для выравнивания").arg(paddingCount),
                "Дополнение блока"));
        }

        // Шаг 6: Шифрование блоков
        QVector<int> encryptedNumbers;
        int blockCount = numbers.size() / size;

        for (int block = 0; block < blockCount; block++) {
            // Извлекаем блок
            QVector<int> blockVector;
            QString blockStr = "Блок " + QString::number(block + 1) + ": [";
            for (int i = 0; i < size; i++) {
                int num = numbers[block * size + i];
                blockVector.append(num);
                blockStr += QString::number(num + 1); // +1 для вывода
                if (i < size - 1) blockStr += " ";
            }
            blockStr += "]";

            steps.append(CipherStep(6 + block * 2, QChar(),
                blockStr,
                QString("Блок %1 (вектор B%2)").arg(block + 1).arg(block + 1)));

            // Умножаем матрицу на вектор
            QVector<int> encryptedBlock = multiplyMatrixVector(matrix, blockVector);

            QString encryptedStr = "→ [";
            for (int i = 0; i < size; i++) {
                encryptedNumbers.append(encryptedBlock[i]);
                encryptedStr += QString::number(encryptedBlock[i]);
                if (i < size - 1) encryptedStr += " ";
            }
            encryptedStr += "]";

            steps.append(CipherStep(7 + block * 2, QChar(),
                encryptedStr,
                QString("Блок %1 после умножения на матрицу (C%2 = A × B%2)").arg(block + 1).arg(block + 1)));
        }

        // Шаг 7: Форматирование результата с ведущими нулями
        QString result = formatNumbers(encryptedNumbers);

        steps.append(CipherStep(6 + blockCount * 2, QChar(),
            "Зашифрованные числа: " + result,
            "Объединение блоков и форматирование"));

        // Формируем описание
        QString description = QString("Матричный шифр\n"
                                    "════════════════════════════════════════\n"
                                    "Размер матрицы: %1x%1\n"
                                    "Определитель: %2\n"
                                    "Матрица обратима: да\n"
                                    "Исходный текст: %3 букв\n"
                                    "Блоков: %4\n"
                                    "Дополнено нулями: %5")
                            .arg(size)
                            .arg(det)
                            .arg(cleanText.length())
                            .arg(blockCount)
                            .arg(paddingCount);

        return CipherResult(result, steps, description, name(), true);

    } catch (const std::exception& e) {
        steps.append(CipherStep(99, QChar(),
            QString("Исключение: %1").arg(e.what()),
            "Ошибка выполнения"));
        return CipherResult("", steps, "Матричный шифр (ошибка)", name(), true);
    }
}

CipherResult MatrixCipher::decrypt(const QString& text, const QVariantMap& params)
{
    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало дешифрования", "Инициализация"));

    try {
        // Шаг 1: Получение и проверка матрицы
        if (!params.contains("matrix")) {
            steps.append(CipherStep(1, QChar(), "Ошибка: матрица не задана", "Проверка параметров"));
            return CipherResult("", steps, "Матричный шифр (дешифрование, ошибка)", name() + " (дешифрование)", false);
        }

        QString matrixStr = params["matrix"].toString();
        QVector<QVector<int>> matrix;

        if (!parseMatrix(matrixStr, matrix)) {
            steps.append(CipherStep(1, QChar(), "Ошибка: некорректный формат матрицы", "Парсинг матрицы"));
            return CipherResult("", steps, "Матричный шифр (дешифрование, ошибка)", name() + " (дешифрование)", false);
        }

        int size = matrix.size();

        // Форматируем матрицу для вывода
        QString matrixDisplay;
        for (int i = 0; i < size; i++) {
            matrixDisplay += "[";
            for (int j = 0; j < size; j++) {
                matrixDisplay += QString::number(matrix[i][j]);
                if (j < size - 1) matrixDisplay += " ";
            }
            matrixDisplay += "]\n";
        }

        steps.append(CipherStep(1, QChar(),
            QString("Ключевая матрица %1x%1:\n%2").arg(size).arg(matrixDisplay),
            "Загрузка матрицы"));

        // Шаг 2: Проверка обратимости и вычисление определителя
        int det;
        if (!isInvertible(matrix, det)) {
            steps.append(CipherStep(2, QChar(),
                QString("Ошибка: матрица необратима (det = %1)").arg(det),
                "Проверка обратимости"));
            return CipherResult("", steps, "Матричный шифр (дешифрование, ошибка)", name() + " (дешифрование)", false);
        }

        steps.append(CipherStep(2, QChar(),
            QString("Определитель матрицы: det = %1").arg(det),
            "Вычисление определителя"));

        // Шаг 3: Вычисление обратной матрицы
        QVector<QVector<double>> inverseMatrix;
        if (!calculateInverse(matrix, inverseMatrix, det)) {
            steps.append(CipherStep(3, QChar(), "Ошибка: не удалось вычислить обратную матрицу", "Вычисление обратной матрицы"));
            return CipherResult("", steps, "Матричный шифр (дешифрование, ошибка)", name() + " (дешифрование)", false);
        }

        // Форматируем обратную матрицу для вывода
        QString inverseDisplay;
        for (int i = 0; i < size; i++) {
            inverseDisplay += "[";
            for (int j = 0; j < size; j++) {
                // Форматируем с 3 знаками после запятой
                inverseDisplay += QString::number(inverseMatrix[i][j], 'f', 3);
                if (j < size - 1) inverseDisplay += " ";
            }
            inverseDisplay += "]\n";
        }

        steps.append(CipherStep(3, QChar(),
            QString("Обратная матрица %1x%1 (A⁻¹):\n%2").arg(size).arg(inverseDisplay),
            "Вычисление обратной матрицы"));

        // Шаг 4: Парсинг чисел из текста (с учетом ведущих нулей)
        QVector<int> numbers = parseNumbers(text);
        if (numbers.isEmpty()) {
            steps.append(CipherStep(4, QChar(),
                "Ошибка: не удалось распарсить числа",
                "Парсинг чисел"));
            return CipherResult("", steps, "Матричный шифр (дешифрование, ошибка)", name() + " (дешифрование)", false);
        }

        if (numbers.size() % size != 0) {
            steps.append(CipherStep(4, QChar(),
                QString("Ошибка: количество чисел (%1) не кратно размеру блока (%2)").arg(numbers.size()).arg(size),
                "Проверка кратности"));
            return CipherResult("", steps, "Матричный шифр (дешифрование, ошибка)", name() + " (дешифрование)", false);
        }

        QString numbersStr;
        for (int i = 0; i < qMin(10, numbers.size()); i++) {
            numbersStr += QString::number(numbers[i]);
            if (i < qMin(10, numbers.size()) - 1) numbersStr += " ";
        }
        if (numbers.size() > 10) numbersStr += " ...";

        steps.append(CipherStep(4, QChar(),
            QString("Загружено %1 чисел: %2").arg(numbers.size()).arg(numbersStr),
            "Парсинг чисел"));

        // Шаг 5: Дешифрование блоков
        QVector<int> decryptedNumbers;
        int blockCount = numbers.size() / size;

        for (int block = 0; block < blockCount; block++) {
            // Извлекаем блок
            QVector<int> blockVector;
            QString blockStr = "Блок " + QString::number(block + 1) + ": [";
            for (int i = 0; i < size; i++) {
                int num = numbers[block * size + i];
                blockVector.append(num);
                blockStr += QString::number(num);
                if (i < size - 1) blockStr += " ";
            }
            blockStr += "]";

            steps.append(CipherStep(5 + block * 2, QChar(),
                blockStr,
                QString("Блок %1 (вектор C%2)").arg(block + 1).arg(block + 1)));

            // Умножаем на обратную матрицу (double)
            QVector<double> decryptedBlockDouble = multiplyMatrixVectorDouble(inverseMatrix, blockVector);

            // Форматируем промежуточный результат с плавающей точкой
            QString doubleStr = "→ [";
            for (int i = 0; i < size; i++) {
                doubleStr += QString::number(decryptedBlockDouble[i], 'f', 3);
                if (i < size - 1) doubleStr += " ";
            }
            doubleStr += "] (до округления)";

            steps.append(CipherStep(6 + block * 2 - 1, QChar(),
                doubleStr,
                QString("Блок %1 после умножения на A⁻¹").arg(block + 1)));

            // Округляем до целых чисел
            QVector<int> decryptedBlock = roundToInt(decryptedBlockDouble);

            QString decryptedStr = "→ [";
            for (int i = 0; i < size; i++) {
                decryptedNumbers.append(decryptedBlock[i]);
                decryptedStr += QString::number(decryptedBlock[i] + 1); // +1 для вывода
                if (i < size - 1) decryptedStr += " ";
            }
            decryptedStr += "] (после округления)";

            steps.append(CipherStep(6 + block * 2, QChar(),
                decryptedStr,
                QString("Блок %1 расшифрован (B%2 = A⁻¹ × C%2)").arg(block + 1).arg(block + 1)));
        }

        // Шаг 6: Преобразование чисел в текст
        QString decryptedText = numbersToText(decryptedNumbers);

        // Убираем дополнение (нули в конце)
        int originalLength = decryptedText.length();
        while (!decryptedText.isEmpty() && decryptedText.back() == ALPHABET[0]) {
            decryptedText.chop(1);
        }
        int paddingRemoved = originalLength - decryptedText.length();

        if (paddingRemoved > 0) {
            steps.append(CipherStep(5 + blockCount * 2, QChar(),
                QString("Удалено %1 добавленных букв А").arg(paddingRemoved),
                "Удаление дополнения"));
        }

        steps.append(CipherStep(6 + blockCount * 2, QChar(),
            "Расшифрованный текст: " + decryptedText,
            "Преобразование чисел в текст"));

        // Формируем описание
        QString description = QString("Дешифрование матричного шифра\n"
                                    "════════════════════════════════════════\n"
                                    "Размер матрицы: %1x%1\n"
                                    "Определитель: %2\n"
                                    "Блоков: %3\n"
                                    "Получено букв: %4\n"
                                    "Удалено дополнений: %5")
                            .arg(size)
                            .arg(det)
                            .arg(blockCount)
                            .arg(decryptedText.length())
                            .arg(paddingRemoved);

        return CipherResult(decryptedText, steps, description, name() + " (дешифрование)", false);

    } catch (const std::exception& e) {
        steps.append(CipherStep(99, QChar(),
            QString("Исключение: %1").arg(e.what()),
            "Ошибка выполнения"));
        return CipherResult("", steps, "Матричный шифр (дешифрование, ошибка)", name() + " (дешифрование)", false);
    }
}

QString MatrixCipher::name() const {
    return QStringLiteral(u"Матричный шифр");
}

QString MatrixCipher::description() const {
    return QStringLiteral(u"Шифрование с использованием матричного умножения. "
                         "Текст разбивается на блоки, которые умножаются на квадратную матрицу по модулю 32.");
}

// Вспомогательные методы

bool MatrixCipher::parseMatrix(const QString& matrixStr, QVector<QVector<int>>& matrix) {
    matrix.clear();

    QStringList lines = matrixStr.split('\n', Qt::SkipEmptyParts);
    if (lines.isEmpty()) {
        // Пробуем разделить пробелами
        lines = matrixStr.split(' ', Qt::SkipEmptyParts);
        if (lines.isEmpty()) return false;

        // Предполагаем квадратную матрицу
        int total = lines.size();
        int size = sqrt(total);
        if (size * size != total || size < 2) return false;

        matrix.resize(size);
        for (int i = 0; i < size; i++) {
            matrix[i].resize(size);
            for (int j = 0; j < size; j++) {
                bool ok;
                int val = lines[i * size + j].toInt(&ok);
                if (!ok) return false;
                matrix[i][j] = val;
            }
        }
    } else {
        // Матрица по строкам
        int size = lines.size();
        matrix.resize(size);

        for (int i = 0; i < size; i++) {
            QStringList values = lines[i].split(' ', Qt::SkipEmptyParts);
            if (values.size() != size) return false;

            matrix[i].resize(size);
            for (int j = 0; j < size; j++) {
                bool ok;
                int val = values[j].toInt(&ok);
                if (!ok) return false;
                matrix[i][j] = val;
            }
        }
    }

    return true;
}

bool MatrixCipher::isInvertible(const QVector<QVector<int>>& matrix, int& det) {
    det = calculateDeterminant(matrix);
    return det != 0;
}

int MatrixCipher::calculateDeterminant(const QVector<QVector<int>>& matrix) {
    int size = matrix.size();

    if (size == 1) {
        return matrix[0][0];
    }

    if (size == 2) {
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
    }

    int det = 0;
    int sign = 1;

    for (int col = 0; col < size; col++) {
        // Создаем минор
        QVector<QVector<int>> minor(size - 1, QVector<int>(size - 1));

        for (int i = 1; i < size; i++) {
            int minorCol = 0;
            for (int j = 0; j < size; j++) {
                if (j == col) continue;
                minor[i - 1][minorCol++] = matrix[i][j];
            }
        }

        det += sign * matrix[0][col] * calculateDeterminant(minor);
        sign = -sign;
    }

    return det;
}

int MatrixCipher::calculateMinor(const QVector<QVector<int>>& matrix, int row, int col) {
    int size = matrix.size();
    QVector<QVector<int>> minor(size - 1, QVector<int>(size - 1));

    int minorRow = 0;
    for (int i = 0; i < size; i++) {
        if (i == row) continue;

        int minorCol = 0;
        for (int j = 0; j < size; j++) {
            if (j == col) continue;
            minor[minorRow][minorCol++] = matrix[i][j];
        }
        minorRow++;
    }

    return calculateDeterminant(minor);
}

bool MatrixCipher::calculateInverse(const QVector<QVector<int>>& matrix, QVector<QVector<double>>& inverse, int det) {
    int size = matrix.size();

    if (det == 0) return false;

    inverse.resize(size, QVector<double>(size));

    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            int minor = calculateMinor(matrix, i, j);
            int cofactor = ((i + j) % 2 == 0 ? 1 : -1) * minor;
            // Транспонируем и делим на определитель
            inverse[j][i] = static_cast<double>(cofactor) / det;
        }
    }

    return true;
}

QVector<int> MatrixCipher::textToNumbers(const QString& text) {
    QVector<int> numbers;

    for (const QChar& ch : text) {
        int index = ALPHABET.indexOf(ch);
        if (index >= 0) {
            numbers.append(index); // А=0, Б=1, ..., Я=31
        }
    }

    return numbers;
}

QString MatrixCipher::numbersToText(const QVector<int>& numbers) {
    QString text;

    for (int num : numbers) {
        // Проверяем, что число в пределах алфавита
        if (num >= 0 && num < ALPHABET_SIZE) {
            text.append(ALPHABET[num]);
        } else {
            // Если число вне диапазона, добавляем '?'
            text.append('?');
        }
    }

    return text;
}

QVector<int> MatrixCipher::multiplyMatrixVector(const QVector<QVector<int>>& matrix, const QVector<int>& vector) {
    int size = matrix.size();
    QVector<int> result(size, 0);

    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            result[i] += matrix[i][j] * vector[j];
        }
    }

    return result;
}

// Умножение на обратную матрицу (double)
QVector<double> MatrixCipher::multiplyMatrixVectorDouble(const QVector<QVector<double>>& matrix, const QVector<int>& vector) {
    int size = matrix.size();
    QVector<double> result(size, 0.0);

    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            result[i] += matrix[i][j] * vector[j];
        }
    }

    return result;
}

QVector<int> MatrixCipher::roundToInt(const QVector<double>& numbers) {
    QVector<int> result;
    for (double num : numbers) {
        result.append(qRound(num));
    }
    return result;
}

QString MatrixCipher::formatNumbers(const QVector<int>& numbers) {
    if (numbers.isEmpty()) return QString();

    // Находим максимальное число для определения разрядности
    int maxNum = 0;
    for (int num : numbers) {
        if (qAbs(num) > maxNum) maxNum = qAbs(num);
    }

    int width = QString::number(maxNum).length();

    QString result;
    for (int i = 0; i < numbers.size(); i++) {
        if (i > 0) result += " ";
        QString numStr = QString::number(numbers[i]);
        // Дополняем ведущими нулями
        result += numStr.rightJustified(width, '0');
    }

    return result;
}

QVector<int> MatrixCipher::parseNumbers(const QString& text) {
    QVector<int> numbers;

    QStringList parts = text.split(' ', Qt::SkipEmptyParts);
    for (const QString& part : parts) {
        bool ok;
        // Убираем ведущие нули перед преобразованием
        QString cleanPart = part;
        while (cleanPart.startsWith('0') && cleanPart.length() > 1) {
            cleanPart.remove(0, 1);
        }
        int num = cleanPart.toInt(&ok);
        if (ok) {
            numbers.append(num);
        }
    }

    return numbers;
}

// Улучшенная функция проверки матрицы
bool MatrixCipher::checkMatrix(const QString& matrixStr, QString& resultMessage, int& det, int& size) {
    QVector<QVector<int>> matrix;

    // Проверяем парсинг
    if (!parseMatrix(matrixStr, matrix)) {
        resultMessage = "Ошибка: некорректный формат матрицы";
        return false;
    }

    size = matrix.size();

    // Проверяем квадратность (уже должно быть, но на всякий случай)
    for (int i = 0; i < size; i++) {
        if (matrix[i].size() != size) {
            resultMessage = "Ошибка: матрица не является квадратной";
            return false;
        }
    }

    // Проверяем обратимость
    det = calculateDeterminant(matrix);
    if (det == 0) {
        resultMessage = QString("Ошибка: матрица необратима (определитель = %1)").arg(det);
        return false;
    }

    // Проверяем, что определитель не слишком большой для вычислений
    if (qAbs(det) > 1000000) {
        resultMessage = QString("Предупреждение: большой определитель (%1). Возможны проблемы с точностью.").arg(det);
        return true; // Всё равно возвращаем true, но с предупреждением
    }

    resultMessage = QString("✓ Матрица %1x%1 обратима. Определитель = %2").arg(size).arg(det);
    return true;
}

MatrixCipherRegister::MatrixCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "matrix",
        "Матричный шифр",
        []() -> CipherInterface* { return new MatrixCipher(); }
    );

    // Регистрируем основные виджеты (минимум на главном экране)
    CipherWidgetFactory::instance().registerCipherWidgets(
        "matrix",
        // Основные виджеты (на главном экране)
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QLabel* infoLabel = new QLabel("Ключ: квадратная обратимая матрица", parent);
            infoLabel->setStyleSheet("color: #7f8c8d; font-style: italic;");
            infoLabel->setWordWrap(true);
            layout->addWidget(infoLabel);
        },
        // Расширенные виджеты (в отдельном окне)
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {

            // Создаем горизонтальный макет для двух колонок
            QHBoxLayout* mainHorizontalLayout = new QHBoxLayout();
            mainHorizontalLayout->setSpacing(20);

            // === ЛЕВАЯ КОЛОНКА ===
            QVBoxLayout* leftColumnLayout = new QVBoxLayout();
            leftColumnLayout->setSpacing(10);

            // Основной контейнер для настроек матрицы
            QGroupBox* matrixGroupBox = new QGroupBox("Параметры матрицы", parent);
            QVBoxLayout* groupLayout = new QVBoxLayout(matrixGroupBox);

            // Пояснительный текст
            QLabel* helpLabel = new QLabel(
                "Введите квадратную матрицу. Форматы:\n"
                "• Строки через пробелы, разделенные переносом строки\n"
                "• Все элементы через пробелы (автоматически определятся как квадратная)",
                parent
            );
            helpLabel->setWordWrap(true);
            helpLabel->setStyleSheet("color: #a0a0a0; font-size: 10px; padding: 4px;");
            groupLayout->addWidget(helpLabel);

            // Поле для ввода матрицы
            QTextEdit* matrixTextEdit = new QTextEdit(parent);
            matrixTextEdit->setObjectName("matrix");
            matrixTextEdit->setPlainText("8 4 1\n2 7 3\n5 9 6");
            matrixTextEdit->setMinimumHeight(150);
            matrixTextEdit->setMaximumHeight(200);
            matrixTextEdit->setToolTip("Пример: 8 4 1\\n2 7 3\\n5 9 6 - матрица 3x3");
            groupLayout->addWidget(matrixTextEdit);
            widgets["matrix"] = matrixTextEdit;

            // Горизонтальная панель с кнопками
            QHBoxLayout* buttonLayout = new QHBoxLayout();
            buttonLayout->setSpacing(8);

            QPushButton* checkButton = new QPushButton("Проверить матрицу", parent);
            checkButton->setObjectName("checkMatrixButton");
            checkButton->setMinimumWidth(130);
            checkButton->setMaximumWidth(150);
            buttonLayout->addWidget(checkButton);

            QPushButton* clearButton = new QPushButton("Очистить", parent);
            clearButton->setObjectName("clearMatrixButton");
            clearButton->setMinimumWidth(90);
            clearButton->setMaximumWidth(100);
            buttonLayout->addWidget(clearButton);

            buttonLayout->addStretch();
            groupLayout->addLayout(buttonLayout);

            // Информационное поле под кнопками
            QLabel* infoLabel = new QLabel(parent);
            infoLabel->setObjectName("matrixInfoLabel");
            infoLabel->setWordWrap(true);
            infoLabel->setText("Матрица не проверена");
            infoLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 8px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px;");
            infoLabel->setProperty("status", "info");
            infoLabel->setMinimumHeight(40);
            groupLayout->addWidget(infoLabel);

            leftColumnLayout->addWidget(matrixGroupBox);

            // Группа с предустановленными размерами
            QGroupBox* presetsGroupBox = new QGroupBox("Быстрый выбор размера матрицы", parent);
            QVBoxLayout* presetsLayout = new QVBoxLayout(presetsGroupBox);

            QHBoxLayout* sizeButtonsLayout = new QHBoxLayout();
            sizeButtonsLayout->setSpacing(12);

            QPushButton* size2Button = new QPushButton("2x2", parent);
            size2Button->setObjectName("size2Button");
            size2Button->setMinimumWidth(80);
            size2Button->setMaximumWidth(100);
            size2Button->setMinimumHeight(32);
            size2Button->setStyleSheet("font-weight: bold; font-size: 12px; border: 1px solid #3a7afe; background-color: rgba(58, 122, 254, 0.1);");
            sizeButtonsLayout->addWidget(size2Button);

            QPushButton* size3Button = new QPushButton("3x3", parent);
            size3Button->setObjectName("size3Button");
            size3Button->setMinimumWidth(80);
            size3Button->setMaximumWidth(100);
            size3Button->setMinimumHeight(32);
            size3Button->setStyleSheet("font-weight: bold; font-size: 12px; border: 1px solid #3a7afe; background-color: rgba(58, 122, 254, 0.1);");
            sizeButtonsLayout->addWidget(size3Button);

            QPushButton* size4Button = new QPushButton("4x4", parent);
            size4Button->setObjectName("size4Button");
            size4Button->setMinimumWidth(80);
            size4Button->setMaximumWidth(100);
            size4Button->setMinimumHeight(32);
            size4Button->setStyleSheet("font-weight: bold; font-size: 12px; border: 1px solid #3a7afe; background-color: rgba(58, 122, 254, 0.1);");
            sizeButtonsLayout->addWidget(size4Button);

            sizeButtonsLayout->addStretch();
            presetsLayout->addLayout(sizeButtonsLayout);

            leftColumnLayout->addWidget(presetsGroupBox);

            // Добавляем растяжение в левой колонке
            leftColumnLayout->addStretch();

            // === ПРАВАЯ КОЛОНКА ===
            QVBoxLayout* rightColumnLayout = new QVBoxLayout();
            rightColumnLayout->setSpacing(10);

            // Группа информации о текущей матрице
            QGroupBox* infoGroupBox = new QGroupBox("Информация о матрице", parent);
            QVBoxLayout* infoLayout = new QVBoxLayout(infoGroupBox);
            infoLayout->setSpacing(12);

            // Размер матрицы
            QLabel* sizeTitleLabel = new QLabel("Размер матрицы:", parent);
            sizeTitleLabel->setStyleSheet("font-weight: bold; color: #a0a0a0;");
            infoLayout->addWidget(sizeTitleLabel);

            QLabel* sizeInfoLabel = new QLabel("не определен", parent);
            sizeInfoLabel->setObjectName("sizeInfoLabel");
            sizeInfoLabel->setStyleSheet("padding: 10px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px; font-size: 14px;");
            sizeInfoLabel->setMinimumHeight(40);
            infoLayout->addWidget(sizeInfoLabel);

            // Определитель
            QLabel* detTitleLabel = new QLabel("Определитель:", parent);
            detTitleLabel->setStyleSheet("font-weight: bold; color: #a0a0a0; margin-top: 8px;");
            infoLayout->addWidget(detTitleLabel);

            QLabel* detInfoLabel = new QLabel("не вычислен", parent);
            detInfoLabel->setObjectName("detInfoLabel");
            detInfoLabel->setStyleSheet("padding: 10px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px; font-size: 14px;");
            detInfoLabel->setMinimumHeight(40);
            infoLayout->addWidget(detInfoLabel);

            // Обратимость
            QLabel* invertibleTitleLabel = new QLabel("Обратимость:", parent);
            invertibleTitleLabel->setStyleSheet("font-weight: bold; color: #a0a0a0; margin-top: 8px;");
            infoLayout->addWidget(invertibleTitleLabel);

            QLabel* invertibleInfoLabel = new QLabel("неизвестно", parent);
            invertibleInfoLabel->setObjectName("invertibleInfoLabel");
            invertibleInfoLabel->setStyleSheet("padding: 10px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px; font-size: 14px;");
            invertibleInfoLabel->setMinimumHeight(40);
            infoLayout->addWidget(invertibleInfoLabel);

            // Добавляем растяжение в правой колонке
            infoLayout->addStretch();

            rightColumnLayout->addWidget(infoGroupBox);
            rightColumnLayout->addStretch();

            // Добавляем обе колонки в основной горизонтальный макет
            mainHorizontalLayout->addLayout(leftColumnLayout, 1); // 1 - коэффициент растяжения
            mainHorizontalLayout->addLayout(rightColumnLayout, 1); // 1 - коэффициент растяжения

            // Добавляем горизонтальный макет в основной вертикальный layout
            layout->addLayout(mainHorizontalLayout);

            // Подключаем сигналы с обновленной логикой проверки
            QObject::connect(checkButton, &QPushButton::clicked, parent,
                [matrixTextEdit, infoLabel, sizeInfoLabel, detInfoLabel, invertibleInfoLabel]() {
                    QString text = matrixTextEdit->toPlainText().trimmed();
                    QString message;
                    int det = 0;
                    int size = 0;

                    bool valid = MatrixCipher::checkMatrix(text, message, det, size);

                    // Обновляем информационные метки
                    if (valid) {
                        infoLabel->setText(message);
                        infoLabel->setProperty("status", "success");
                        infoLabel->setStyleSheet("color: #27ae60; padding: 8px; background-color: #1e3a2a; border: 1px solid #27ae60; border-radius: 4px;");

                        sizeInfoLabel->setText(QString::number(size));
                        sizeInfoLabel->setStyleSheet("padding: 10px; background-color: #1e3a2a; border: 2px solid #27ae60; border-radius: 4px; color: #27ae60; font-size: 16px; font-weight: bold;");

                        detInfoLabel->setText(QString::number(det));
                        detInfoLabel->setStyleSheet("padding: 10px; background-color: #1e3a2a; border: 2px solid #27ae60; border-radius: 4px; color: #27ae60; font-size: 16px; font-weight: bold;");

                        invertibleInfoLabel->setText("ДА ✓");
                        invertibleInfoLabel->setStyleSheet("padding: 10px; background-color: #1e3a2a; border: 2px solid #27ae60; border-radius: 4px; color: #27ae60; font-size: 16px; font-weight: bold;");
                    } else {
                        infoLabel->setText(message);
                        infoLabel->setProperty("status", "error");
                        infoLabel->setStyleSheet("color: #e74c3c; padding: 8px; background-color: #3a1e1e; border: 1px solid #e74c3c; border-radius: 4px;");

                        if (size > 0) {
                            sizeInfoLabel->setText(QString::number(size));
                            sizeInfoLabel->setStyleSheet("padding: 10px; background-color: #3a1e1e; border: 2px solid #e74c3c; border-radius: 4px; color: #e74c3c; font-size: 16px; font-weight: bold;");
                        } else {
                            sizeInfoLabel->setText("?");
                            sizeInfoLabel->setStyleSheet("padding: 10px; background-color: #3a1e1e; border: 2px solid #e74c3c; border-radius: 4px; color: #e74c3c; font-size: 16px; font-weight: bold;");
                        }

                        if (det != 0) {
                            detInfoLabel->setText(QString::number(det));
                            detInfoLabel->setStyleSheet("padding: 10px; background-color: #3a1e1e; border: 2px solid #e74c3c; border-radius: 4px; color: #e74c3c; font-size: 16px; font-weight: bold;");
                        } else {
                            detInfoLabel->setText("0");
                            detInfoLabel->setStyleSheet("padding: 10px; background-color: #3a1e1e; border: 2px solid #e74c3c; border-radius: 4px; color: #e74c3c; font-size: 16px; font-weight: bold;");
                        }

                        invertibleInfoLabel->setText("НЕТ ✗");
                        invertibleInfoLabel->setStyleSheet("padding: 10px; background-color: #3a1e1e; border: 2px solid #e74c3c; border-radius: 4px; color: #e74c3c; font-size: 16px; font-weight: bold;");
                    }
                });

            QObject::connect(clearButton, &QPushButton::clicked, parent,
                [matrixTextEdit, infoLabel, sizeInfoLabel, detInfoLabel, invertibleInfoLabel]() {
                    matrixTextEdit->clear();
                    infoLabel->setText("Матрица не проверена");
                    infoLabel->setProperty("status", "info");
                    infoLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 8px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px;");

                    sizeInfoLabel->setText("не определен");
                    sizeInfoLabel->setStyleSheet("padding: 10px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px; font-size: 14px;");

                    detInfoLabel->setText("не вычислен");
                    detInfoLabel->setStyleSheet("padding: 10px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px; font-size: 14px;");

                    invertibleInfoLabel->setText("неизвестно");
                    invertibleInfoLabel->setStyleSheet("padding: 10px; background-color: #2d2d2d; border: 1px solid #404040; border-radius: 4px; font-size: 14px;");
                });

            // Кнопки быстрого выбора размера
            QObject::connect(size2Button, &QPushButton::clicked, parent,
                [matrixTextEdit]() {
                    matrixTextEdit->setPlainText("3 1\n5 2");
                });

            QObject::connect(size3Button, &QPushButton::clicked, parent,
                [matrixTextEdit]() {
                    matrixTextEdit->setPlainText("8 4 1\n2 7 3\n5 9 6");
                });

            QObject::connect(size4Button, &QPushButton::clicked, parent,
                [matrixTextEdit]() {
                    matrixTextEdit->setPlainText("1 2 3 4\n0 1 2 3\n0 0 1 2\n0 0 0 1");
                });
        }
    );
}

// Статический регистратор
static MatrixCipherRegister matrixCipherRegister;
