#include "columntranspositioncipher.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "routecipherwidget.h"
#include <QDebug>
#include <QLineEdit>
#include <QLabel>
#include <QHBoxLayout>

const QString ColumnTranspositionCipher::RUSSIAN_ALPHABET = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

ColumnTranspositionCipher::ColumnTranspositionCipher()
    : RouteCipher()
{
}

QString ColumnTranspositionCipher::name() const
{
    return QStringLiteral(u"ColumnTranspositionCipher");
}

QString ColumnTranspositionCipher::description() const
{
    return QStringLiteral(u"Шифр вертикальной перестановки. "
                          "Ключ-слово определяет порядок чтения столбцов. "
                          "Направления строк и размер таблицы настраиваются в расширенных параметрах.");
}

QVector<int> ColumnTranspositionCipher::keyToColumnOrder(const QString& key, int columnCount, QString& errorMessage)
{
    QString cleanKey = CipherUtils::filterAlphabetOnly(key.toUpper(), RUSSIAN_ALPHABET);

    if (cleanKey.isEmpty()) {
        errorMessage = "Ключ должен содержать хотя бы одну букву русского алфавита";
        return {};
    }

    if (cleanKey.length() != columnCount) {
        errorMessage = QString("Длина ключа (%1) не соответствует количеству столбцов (%2)")
                              .arg(cleanKey.length()).arg(columnCount);
        return {};
    }

    QVector<QPair<QChar, int>> letters;
    for (int i = 0; i < cleanKey.length(); ++i) {
        letters.append(qMakePair(cleanKey[i], i));
    }

    std::stable_sort(letters.begin(), letters.end(),
        [](const QPair<QChar, int>& a, const QPair<QChar, int>& b) {
            return a.first < b.first;
        });

    QVector<int> order(columnCount, 0);
    for (int i = 0; i < letters.size(); ++i) {
        order[letters[i].second] = i + 1;
    }

    return order;
}

CipherResult ColumnTranspositionCipher::process(const QString& text, const QVariantMap& params, bool encrypt)
{
    QString cleanText = CipherUtils::filterAlphabetOnly(text, RUSSIAN_ALPHABET);

    // Ключ
    QString key = params.value("key", "").toString();

    // Размеры
    int rows = params.value("rows", 0).toInt();
    int cols = params.value("cols", 0).toInt();

    if (rows <= 0 || cols <= 0) {
        getOptimalSize(cleanText.length(), rows, cols);
    }

    // Проверка ключа
    QString errorMessage;
    QVector<int> columnOrder = keyToColumnOrder(key, cols, errorMessage);
    if (columnOrder.isEmpty()) {
        return CipherResult(errorMessage, QVector<CipherStep>(), "Ошибка", name(), true);
    }

    // writeDirections
    QVector<Direction> writeDirections;
    if (params.contains("writeDirections")) {
        QVariantList dirList = params.value("writeDirections").toList();
        for (const QVariant& v : dirList) writeDirections.append(static_cast<Direction>(v.toInt()));
    } else {
        writeDirections = getDefaultWriteDirections(rows);
    }

    // readDirections
    QVector<Direction> readDirections;
    if (params.contains("readDirections")) {
        QVariantList dirList = params.value("readDirections").toList();
        for (const QVariant& v : dirList) readDirections.append(static_cast<Direction>(v.toInt()));
    } else {
        readDirections = QVector<Direction>(cols, TOP_TO_BOTTOM);
    }

    // rowOrder
    QVector<int> rowOrder;
    if (params.contains("rowOrder")) {
        QVariantList orderList = params.value("rowOrder").toList();
        for (const QVariant& v : orderList) rowOrder.append(v.toInt());
    } else {
        for (int i = 1; i <= rows; ++i) rowOrder.append(i);
    }


    if (encrypt) {
        return encryptImpl(cleanText, rows, cols, writeDirections, columnOrder);
    } else {
        return decryptImpl(cleanText, rows, cols, writeDirections, readDirections, rowOrder, columnOrder);
    }
}

CipherResult ColumnTranspositionCipher::encrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, true);
}

CipherResult ColumnTranspositionCipher::decrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, false);
}

CipherResult ColumnTranspositionCipher::decryptImpl(const QString& text,
                                                   int rows, int cols,
                                                   const QVector<Direction>& writeDirections,
                                                   const QVector<Direction>& readDirections,
                                                   const QVector<int>& rowOrder,
                                                   const QVector<int>& columnOrder)
{
    QVector<CipherStep> steps;

    // Шаг 1: Очистка текста
    QString cleanText = CipherUtils::filterAlphabetOnly(text, RUSSIAN_ALPHABET);
    int textLen = cleanText.length();
    int totalCells = rows * cols;
    int shortCols = totalCells - textLen;


    steps.append(CipherStep(1, QChar(), cleanText, QStringLiteral(u"Очищенный текст (шифртекст)")));

    // Шаг 2: Информация о размере таблицы
    steps.append(CipherStep(2, QChar(),
        QString("%1×%2").arg(rows).arg(cols),
        QStringLiteral(u"Размер таблицы")));

    // Нормализуем порядки
    QVector<int> normalizedRowOrder = normalizeOrder(rowOrder, rows, "строк");
    QVector<int> normalizedColumnOrder = normalizeOrder(columnOrder, cols, "столбцов");


    // Шаг 3: Создаем пустую таблицу
    std::vector<std::vector<QChar>> table(rows, std::vector<QChar>(cols, QChar()));

    // Шаг 4: Заполняем таблицу по столбцам в порядке columnOrder
    int textIndex = 0;
    shortCols = totalCells - textLen;


    // Определяем направление последней заполненной строки
    Direction lastRowDir = writeDirections[rows - 1];

    // Определяем, какие столбцы короткие
    QVector<bool> isShort(cols, false);
    if (lastRowDir == LEFT_TO_RIGHT) {
        // Пустые ячейки в конце строки → короткие столбцы справа
        for (int i = cols - shortCols; i < cols; ++i) {
            isShort[i] = true;
        }
    } else {
        // Пустые ячейки в начале строки → короткие столбцы слева
        for (int i = 0; i < shortCols; ++i) {
            isShort[i] = true;
        }
    }
    // Создаем список столбцов с их высотой
    QVector<int> columnHeights(cols, rows);
    for (int colIdx = 0; colIdx < cols; ++colIdx) {
        if (isShort[colIdx]) {
            columnHeights[colIdx] = rows - 1;
        }
    }

    // Сортируем столбцы по порядку чтения (columnOrder)
    QVector<QPair<int, int>> columnsByOrder;
    for (int colIdx = 0; colIdx < cols; ++colIdx) {
        columnsByOrder.append(qMakePair(columnOrder[colIdx], colIdx));
    }
    std::sort(columnsByOrder.begin(), columnsByOrder.end());

    // Заполняем таблицу
    for (const auto& item : columnsByOrder) {
        int readOrder = item.first;
        int colIdx = item.second;
        int colHeight = columnHeights[colIdx];


        for (int i = 0; i < colHeight && textIndex < textLen; ++i) {
            table[i][colIdx] = cleanText[textIndex];
            textIndex++;
        }
    }

    // Шаг 5: Отображение заполненной таблицы
    QString tableDisplay;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (table[i][j].isNull()) {
                tableDisplay += '.';
            } else {
                tableDisplay += table[i][j];
            }
        }
        if (i < rows - 1) tableDisplay += "\n";
    }

    steps.append(CipherStep(steps.size() + 1, QChar(),
        tableToString(table), QStringLiteral(u"Таблица, заполненная по столбцам")));

    // Шаг 6: Чтение таблицы по строкам в порядке rowOrder
    QString decrypted;

    // Создаем карту порядка строк: позиция -> индекс строки
    QVector<int> rowIndexByOrder(rows);
    for (int i = 0; i < rows; ++i) {
        rowIndexByOrder[normalizedRowOrder[i] - 1] = i;
    }

    for (int orderNum = 1; orderNum <= rows; ++orderNum) {
        int rowIdx = rowIndexByOrder[orderNum - 1];

        // Определяем направление чтения (используем writeDirections)
        Direction direction = writeDirections[rowIdx];


        QString rowChars;

        if (direction == LEFT_TO_RIGHT) {
            for (int j = 0; j < cols; ++j) {
                if (!table[rowIdx][j].isNull()) {
                    decrypted += table[rowIdx][j];
                    rowChars += table[rowIdx][j];
                }
            }
        } else {
            for (int j = cols - 1; j >= 0; --j) {
                if (!table[rowIdx][j].isNull()) {
                    decrypted += table[rowIdx][j];
                    rowChars += table[rowIdx][j];
                }
            }
        }


        steps.append(CipherStep(
            steps.size() + 1,
            QChar(),
            rowChars,
            QString("Чтение строки %1 (порядок %2): %3")
                .arg(rowIdx + 1)
                .arg(orderNum)
                .arg(direction == LEFT_TO_RIGHT ? "слева направо" : "справа налево")
        ));
    }

    // Шаг 7: Итоговый результат

    steps.append(CipherStep(steps.size() + 1, QChar(),
        decrypted, QStringLiteral(u"Итоговый расшифрованный текст")));

    // Перенумеровываем шаги
    for (int i = 0; i < steps.size(); ++i) {
        steps[i].index = i + 1;
    }

    // Формируем описание
    QString description = QStringLiteral(u"ColumnTranspositionCipher - расшифрование\n")
                        + QStringLiteral(u"Размер таблицы: %1×%2\n").arg(rows).arg(cols)
                        + QStringLiteral(u"Ключ определяет порядок столбцов\n");

    return CipherResult(decrypted, steps, description, name() + " (расшифрование)", false);
}

CipherResult ColumnTranspositionCipher::encryptImpl(const QString& text,
                                                    int rows, int cols,
                                                    const QVector<Direction>& writeDirections,
                                                    const QVector<int>& columnOrder)
{
    QVector<CipherStep> steps;

    // Шаг 1: Очистка текста
    QString cleanText = CipherUtils::filterAlphabetOnly(text, RUSSIAN_ALPHABET);
    steps.append(CipherStep(1, QChar(), cleanText, "Очищенный текст"));

    // Шаг 2: Информация о таблице
    steps.append(CipherStep(2, QChar(),
        QString("%1×%2").arg(rows).arg(cols),
        "Размер таблицы (столбцы = длина ключа)"));

    // Шаг 3: Порядок строк по умолчанию (1..rows)
    QVector<int> rowOrder;
    for (int i = 1; i <= rows; ++i) rowOrder.append(i);

    // Шаг 4: Заполнение таблицы
    QVector<CipherStep> fillSteps;
    auto table = fillTable(cleanText, writeDirections, rowOrder, cols, fillSteps);
    for (const auto& step : fillSteps) steps.append(step);

    // Шаг 5: Отображение таблицы
    steps.append(CipherStep(steps.size() + 1, QChar(),
        tableToString(table), "Заполненная таблица"));

    // Шаг 6: Чтение по столбцам в порядке ключа
    QVector<CipherStep> readSteps;
    QVector<Direction> readDirections(cols, TOP_TO_BOTTOM);
    QString encrypted = readTable(table, readDirections, columnOrder, readSteps);
    for (const auto& step : readSteps) steps.append(step);

    // Шаг 7: Результат
    steps.append(CipherStep(steps.size() + 1, QChar(),
        encrypted, "Итоговый шифртекст"));

    // Перенумеровка
    for (int i = 0; i < steps.size(); ++i) steps[i].index = i + 1;

    return CipherResult(encrypted, steps,
        QString("Вертикальная перестановка\nРазмер таблицы: %1×%2\nКлюч: %3 столбцов")
            .arg(rows).arg(cols).arg(cols),
        name(), false);
}

// ==================== РЕГИСТРАЦИЯ В ФАБРИКЕ ====================

class ColumnTranspositionCipherRegister
{
public:
    ColumnTranspositionCipherRegister()
    {
        CipherFactory::instance().registerCipher(
           11,
            "Вертикальная перестановка",
            []() -> CipherInterface* { return new ColumnTranspositionCipher(); },
            CipherCategory::Permutation
        );

        CipherWidgetFactory::instance().registerCipherWidgets(
            11,
            // Основной виджет - только поле для ключа
            [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
                QHBoxLayout* keyLayout = new QHBoxLayout();
                QLabel* keyLabel = new QLabel("Ключ:");
                QLineEdit* keyLineEdit = new QLineEdit(parent);
                keyLineEdit->setText("ОКТЯБРЬ");
                keyLineEdit->setObjectName("key");
                keyLineEdit->setMaxLength(100);
                keyLineEdit->setClearButtonEnabled(true);
                keyLineEdit->setPlaceholderText("Например: ОКТЯБРЬ");

                keyLayout->addWidget(keyLabel);
                keyLayout->addWidget(keyLineEdit);
                keyLayout->addStretch();
                layout->addLayout(keyLayout);

                widgets["key"] = keyLineEdit;

                QLabel* exampleLabel = new QLabel(parent);
                exampleLabel->setWordWrap(true);
                exampleLabel->setStyleSheet("color: #888; font-size: 10px; padding: 4px;");
                exampleLabel->setText("Ключ определяет порядок перестановки столбцов. "
                                      "Используйте слово из букв русского алфавита.");
                layout->addWidget(exampleLabel);

                qDebug() << "ColumnTranspositionCipher: виджеты созданы";
            },
            // Расширенный виджет - RouteCipherAdvancedWidget
            [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
                RouteCipherAdvancedWidget* advancedWidget = new RouteCipherAdvancedWidget(parent);

                QObject::connect(advancedWidget, &RouteCipherAdvancedWidget::parametersChanged,
                                [advancedWidget]() {
                    qDebug() << "Route widget parameters changed";
                });

                layout->addWidget(advancedWidget);
                widgets["routeAdvancedWidget"] = advancedWidget;
            }
        );
    }
};

// Статический регистратор
static ColumnTranspositionCipherRegister columnTranspositionCipherRegister;
