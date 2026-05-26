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

MatrixCipher::MatrixCipher() {}

CipherResult MatrixCipher::process(const QString& text, const QVariantMap& params, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QString direction = encrypt ? "Шифрование" : "Расшифрование";
    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), QString("Начало %1").arg(direction.toLower()), "Инициализация"));

    try {
        // === Шаг 1: Загрузка и проверка матрицы ===
        if (!params.contains("matrix") || params.value("matrix").toString().trimmed().isEmpty()) {
            result.result = "ОШИБКА: Ключевая матрица не задана!";
            result.steps = steps;
            return result;
        }

        QString matrixStr = params["matrix"].toString();
        QVector<QVector<int>> matrix;

        if (!parseMatrix(matrixStr, matrix)) {
            steps.append(CipherStep(1, QChar(), "Ошибка: некорректный формат матрицы", "Парсинг матрицы"));
            result.result = "Ошибка парсинга матрицы";
            result.steps = steps;
            return result;
        }

        int size = matrix.size();
        steps.append(CipherStep(1, QChar(),
            QString("Ключевая матрица %1x%1:\n%2").arg(size).arg(formatMatrix(matrix)),
            "Загрузка матрицы"));

        // === Шаг 2: Проверка обратимости ===
        int det;
        if (!isInvertible(matrix, det)) {
            steps.append(CipherStep(2, QChar(),
                QString("Ошибка: матрица необратима (det = %1)").arg(det),
                "Проверка обратимости"));
            result.result = QString("Матрица необратима (det = %1)").arg(det);
            result.steps = steps;
            return result;
        }

        steps.append(CipherStep(2, QChar(),
            QString("Определитель матрицы: det = %1").arg(det),
            "Вычисление определителя"));

        // === Шаг 3: Вычисление обратной матрицы ===
        QVector<QVector<double>> inverseMatrix;
        if (!calculateInverse(matrix, inverseMatrix, det)) {
            steps.append(CipherStep(3, QChar(), "Ошибка: не удалось вычислить обратную матрицу", "Обратная матрица"));
            result.result = "Не удалось вычислить обратную матрицу";
            result.steps = steps;
            return result;
        }

        steps.append(CipherStep(3, QChar(),
            QString("Обратная матрица %1x%1:\n%2").arg(size).arg(formatMatrixDouble(inverseMatrix)),
            "Вычисление обратной матрицы"));

        // === Шаг 4: Подготовка данных (различается для encrypt/decrypt) ===
        QVector<int> numbers;
        int stepIndex = 4;

        if (encrypt) {
            // Текст → числа
            QString cleanText = CipherUtils::filterAlphabetOnly(text, m_alphabet);
            if (cleanText.isEmpty()) {
                result.result = "Текст не содержит букв алфавита";
                result.steps = steps;
                return result;
            }

            numbers = CipherUtils::textToNumbers(cleanText, m_alphabet); // 0-31

            steps.append(CipherStep(stepIndex++, QChar(),
                QString("Текст → числа (%1 чисел)").arg(numbers.size()),
                "Преобразование текста"));

            // Дополнение до кратности блоку
            int remainder = numbers.size() % size;
            int paddingCount = (remainder == 0) ? 0 : (size - remainder);

            if (paddingCount > 0) {
                int lastNum = numbers.isEmpty() ? 0 : numbers.last();
                int paddingChar = (lastNum + 1) % m_alphabet.size();
                for (int i = 0; i < paddingCount; i++) {
                    numbers.append(paddingChar);
                }
                steps.append(CipherStep(stepIndex++, QChar(),
                    QString("Добавлено %1 символов для выравнивания").arg(paddingCount),
                    "Дополнение блока"));
            }
        } else {
            // Парсинг чисел
            numbers = parseNumbers(text);
            if (numbers.isEmpty()) {
                result.result = "Не удалось распарсить числа";
                result.steps = steps;
                return result;
            }


            steps.append(CipherStep(stepIndex++, QChar(),
                QString("Загружено %1 чисел").arg(numbers.size()),
                "Парсинг чисел"));
        }

        // === Шаг 5: Обработка блоков ===
        QVector<int> outputNumbers;
        int blockCount = numbers.size() / size;

        for (int block = 0; block < blockCount; block++) {
            QVector<int> blockVector;
            for (int i = 0; i < size; i++) {
                blockVector.append(numbers[block * size + i]);
            }

            steps.append(CipherStep(stepIndex++, QChar(),
                QString("Блок %1: [%2]").arg(block + 1).arg(formatVector(blockVector)),
                QString("Блок %1").arg(block + 1)));

            if (encrypt) {
                // Для умножения: индексы +1 (А=1...Я=32)
                QVector<int> shiftedBlock;
                for (int val : blockVector) shiftedBlock.append(val + 1);

                QVector<int> encryptedBlock = multiplyMatrixVector(matrix, shiftedBlock);
                outputNumbers.append(encryptedBlock);

                steps.append(CipherStep(stepIndex++, QChar(),
                    QString("→ [%1]").arg(formatVector(encryptedBlock)),
                    "Умножение на матрицу"));
            } else {
                QVector<double> decryptedDouble = multiplyMatrixVectorDouble(inverseMatrix, blockVector);
                QVector<int> decryptedBlock = roundToInt(decryptedDouble);

                // Вычитаем 1 для индексов 0-31
                for (int val : decryptedBlock) outputNumbers.append(val - 1);

                steps.append(CipherStep(stepIndex++, QChar(),
                    QString("→ [%1] (после округления)").arg(formatVector(decryptedBlock)),
                    "Умножение на обратную матрицу"));
            }
        }

        // === Шаг 6: Форматирование результата ===
        if (encrypt) {
            QString output = formatNumbers(outputNumbers);
            steps.append(CipherStep(stepIndex, QChar(),
                QString("Результат: %1").arg(output),
                "Форматирование"));
            result.result = output;
        } else {
            QString decryptedText = CipherUtils::numbersToText(outputNumbers, m_alphabet);

            // Удаление паддинга
            if (!decryptedText.isEmpty() && decryptedText.length() > 1) {
                QChar lastChar = decryptedText[decryptedText.length() - 1];
                int removed = 0;
                while (decryptedText.endsWith(lastChar) && decryptedText.length() > 1) {
                    decryptedText.chop(1);
                    removed++;
                }
                if (removed > 0) {
                    steps.append(CipherStep(stepIndex++, QChar(),
                        QString("Удалено %1 добавленных букв '%2'").arg(removed).arg(lastChar),
                        "Удаление паддинга"));
                }
            }

            steps.append(CipherStep(stepIndex, QChar(),
                QString("Расшифрованный текст: %1").arg(decryptedText),
                "Преобразование в текст"));
            result.result = decryptedText;
        }

        result.steps = steps;
        return result;

    } catch (const std::exception& e) {
        steps.append(CipherStep(99, QChar(),
            QString("Исключение: %1").arg(e.what()),
            "Ошибка выполнения"));
        result.result = QString("Ошибка: %1").arg(e.what());
        result.steps = steps;
        return result;
    }
}

CipherResult MatrixCipher::encrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, true);
}

CipherResult MatrixCipher::decrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, false);
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

QString MatrixCipher::formatMatrix(const QVector<QVector<int>>& matrix)
{
    QString result;
    for (int i = 0; i < matrix.size(); i++) {
        result += "[" + formatVector(matrix[i]) + "]\n";
    }
    return result;
}

QString MatrixCipher::formatMatrixDouble(const QVector<QVector<double>>& matrix)
{
    QString result;
    for (int i = 0; i < matrix.size(); i++) {
        result += "[";
        for (int j = 0; j < matrix[i].size(); j++) {
            result += QString::number(matrix[i][j], 'f', 3);
            if (j < matrix[i].size() - 1) result += " ";
        }
        result += "]\n";
    }
    return result;
}

QString MatrixCipher::formatVector(const QVector<int>& vec)
{
    QStringList parts;
    for (int val : vec) parts.append(QString::number(val));
    return parts.join(" ");
}

QVector<int> MatrixCipher::multiplyMatrixVector(const QVector<QVector<int>>& matrix, const QVector<int>& vector) {
    int size = matrix.size();
    QVector<int> result(size, 0);

    // Правильное умножение: result[i] = sum(matrix[i][j] * vector[j])
    // Это и есть умножение матрицы на вектор-столбец
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            result[i] += matrix[i][j] * vector[j];
        }
    }

    return result;
}

// ИСПРАВЛЕННАЯ версия для double
QVector<double> MatrixCipher::multiplyMatrixVectorDouble(const QVector<QVector<double>>& matrix, const QVector<int>& vector) {
    int size = matrix.size();
    QVector<double> result(size, 0.0);

    // То же самое умножение для обратной матрицы
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
        9,
        "Матричный шифр",
        []() -> CipherInterface* { return new MatrixCipher(); },
        CipherCategory::BlockSubstitution
    );

    // Регистрируем основные виджеты (минимум на главном экране)
    CipherWidgetFactory::instance().registerCipherWidgets(
        9,
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

