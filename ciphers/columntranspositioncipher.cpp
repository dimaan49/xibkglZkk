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
    QVector<int> order(columnCount, 0);

    if (key.isEmpty()) {
        errorMessage = "Ключ не может быть пустым";
        return QVector<int>();
    }

    QString cleanKey = CipherUtils::filterAlphabetOnly(key.toUpper(), RUSSIAN_ALPHABET);

    if (cleanKey.isEmpty()) {
        errorMessage = "Ключ должен содержать хотя бы одну букву русского алфавита";
        return QVector<int>();
    }

    if (cleanKey.length() != columnCount) {
        errorMessage = QString("Длина ключа (%1) не соответствует количеству столбцов (%2)")
                              .arg(cleanKey.length()).arg(columnCount);
        return QVector<int>();
    }

    QVector<QPair<QChar, int>> letters;
    for (int i = 0; i < cleanKey.length(); ++i) {
        letters.append(qMakePair(cleanKey[i], i));
    }

    std::stable_sort(letters.begin(), letters.end(),
        [](const QPair<QChar, int>& a, const QPair<QChar, int>& b) {
            return a.first < b.first;
        });

    for (int i = 0; i < letters.size(); ++i) {
        int originalPos = letters[i].second;
        order[originalPos] = i + 1;
    }

    qDebug() << "keyToColumnOrder result:" << order;
    return order;
}

CipherResult ColumnTranspositionCipher::encrypt(const QString& text, const QVariantMap& params)
{
    qDebug() << "\n=== ColumnTranspositionCipher::encrypt ===";

    QString cleanText = CipherUtils::filterAlphabetOnly(text, RUSSIAN_ALPHABET);

    // Получаем ключ из параметров
    QString key = params.value("key", "").toString();
    qDebug() << "Key from params:" << key;

    // Получаем размеры из параметров
    int rows = params.value("rows", 0).toInt();
    int cols = params.value("cols", 0).toInt();

    if (rows <= 0 || cols <= 0) {
        getOptimalSize(cleanText.length(), rows, cols);
        qDebug() << "Auto calculated size:" << rows << "x" << cols;
    }

    // Проверяем ключ
    QString errorMessage;
    QVector<int> columnOrder = keyToColumnOrder(key, cols, errorMessage);

    if (columnOrder.isEmpty()) {
        return CipherResult(errorMessage, QVector<CipherStep>(), "Ошибка", name(), true);
    }

    // ИСПРАВЛЕНО: берём writeDirections из параметров
    QVector<Direction> writeDirections;
    if (params.contains("writeDirections")) {
        QVariantList dirList = params.value("writeDirections").toList();
        for (const QVariant& v : dirList) {
            writeDirections.append(static_cast<Direction>(v.toInt()));
        }
        qDebug() << "writeDirections from params:" << writeDirections.size();
    } else {
        writeDirections = getDefaultWriteDirections(rows);
        qDebug() << "writeDirections from default:" << writeDirections.size();
    }

    // ИСПРАВЛЕНО: берём readDirections из параметров
    QVector<Direction> readDirections;
    if (params.contains("readDirections")) {
        QVariantList dirList = params.value("readDirections").toList();
        for (const QVariant& v : dirList) {
            readDirections.append(static_cast<Direction>(v.toInt()));
        }
        qDebug() << "readDirections from params:" << readDirections.size();
    } else {
        readDirections = QVector<Direction>(cols, TOP_TO_BOTTOM);
        qDebug() << "readDirections from default (all top-to-bottom):" << readDirections.size();
    }

    // ИСПРАВЛЕНО: берём rowOrder из параметров
    QVector<int> rowOrder;
    if (params.contains("rowOrder")) {
        QVariantList orderList = params.value("rowOrder").toList();
        for (const QVariant& v : orderList) {
            rowOrder.append(v.toInt());
        }
        qDebug() << "rowOrder from params:" << rowOrder;
    } else {
        for (int i = 1; i <= rows; ++i) {
            rowOrder.append(i);
        }
        qDebug() << "rowOrder from default:" << rowOrder;
    }

    qDebug() << "columnOrder from key:" << columnOrder;

    return encryptImpl(cleanText, rows, cols, writeDirections, readDirections,
                      rowOrder, columnOrder);
}

CipherResult ColumnTranspositionCipher::decrypt(const QString& text, const QVariantMap& params)
{
    qDebug() << "\n=== ColumnTranspositionCipher::decrypt ===";

    QString cleanText = CipherUtils::filterAlphabetOnly(text, RUSSIAN_ALPHABET);

    // Получаем ключ из параметров
    QString key = params.value("key", "").toString();
    qDebug() << "Key from params:" << key;

    // Получаем размеры из параметров
    int rows = params.value("rows", 0).toInt();
    int cols = params.value("cols", 0).toInt();

    if (rows <= 0 || cols <= 0) {
        getOptimalSize(cleanText.length(), rows, cols);
        qDebug() << "Auto calculated size:" << rows << "x" << cols;
    }

    // Проверяем ключ
    QString errorMessage;
    QVector<int> columnOrder = keyToColumnOrder(key, cols, errorMessage);

    if (columnOrder.isEmpty()) {
        return CipherResult(errorMessage, QVector<CipherStep>(), "Ошибка", name(), true);
    }

    // ИСПРАВЛЕНО: берём writeDirections из параметров
    QVector<Direction> writeDirections;
    if (params.contains("writeDirections")) {
        QVariantList dirList = params.value("writeDirections").toList();
        for (const QVariant& v : dirList) {
            writeDirections.append(static_cast<Direction>(v.toInt()));
        }
        qDebug() << "writeDirections from params:" << writeDirections.size();
    } else {
        writeDirections = getDefaultWriteDirections(rows);
        qDebug() << "writeDirections from default:" << writeDirections.size();
    }

    // ИСПРАВЛЕНО: берём readDirections из параметров
    QVector<Direction> readDirections;
    if (params.contains("readDirections")) {
        QVariantList dirList = params.value("readDirections").toList();
        for (const QVariant& v : dirList) {
            readDirections.append(static_cast<Direction>(v.toInt()));
        }
        qDebug() << "readDirections from params:" << readDirections.size();
    } else {
        readDirections = QVector<Direction>(cols, TOP_TO_BOTTOM);
        qDebug() << "readDirections from default:" << readDirections.size();
    }

    // ИСПРАВЛЕНО: берём rowOrder из параметров
    QVector<int> rowOrder;
    if (params.contains("rowOrder")) {
        QVariantList orderList = params.value("rowOrder").toList();
        for (const QVariant& v : orderList) {
            rowOrder.append(v.toInt());
        }
        qDebug() << "rowOrder from params:" << rowOrder;
    } else {
        for (int i = 1; i <= rows; ++i) {
            rowOrder.append(i);
        }
        qDebug() << "rowOrder from default:" << rowOrder;
    }

    qDebug() << "columnOrder from key:" << columnOrder;

    return decryptImpl(cleanText, rows, cols, writeDirections, readDirections,
                      rowOrder, columnOrder);
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

    qDebug() << "=== decryptImpl ===";
    qDebug() << "rows:" << rows << "cols:" << cols;
    qDebug() << "totalCells:" << totalCells << "textLen:" << textLen << "shortCols:" << shortCols;
    qDebug() << "cleanText:" << cleanText;

    steps.append(CipherStep(1, QChar(), cleanText, QStringLiteral(u"Очищенный текст (шифртекст)")));

    // Шаг 2: Информация о размере таблицы
    steps.append(CipherStep(2, QChar(),
        QString("%1×%2").arg(rows).arg(cols),
        QStringLiteral(u"Размер таблицы")));

    // Нормализуем порядки
    QVector<int> normalizedRowOrder = normalizeOrder(rowOrder, rows, "строк");
    QVector<int> normalizedColumnOrder = normalizeOrder(columnOrder, cols, "столбцов");

    qDebug() << "normalizedRowOrder:" << normalizedRowOrder;
    qDebug() << "normalizedColumnOrder:" << normalizedColumnOrder;

    // Шаг 3: Создаем пустую таблицу
    std::vector<std::vector<QChar>> table(rows, std::vector<QChar>(cols, QChar()));

    // Шаг 4: Заполняем таблицу по столбцам в порядке columnOrder
    int textIndex = 0;
    shortCols = totalCells - textLen;

    qDebug() << "shortCols:" << shortCols;

    // Определяем, какие столбцы короткие (имеют rows-1 символов)
    // При шифровании последняя строка заполнялась справа налево (змейка)
    // Значит, пустые ячейки находятся в начале строки (первые shortCols столбцов)
    QVector<bool> isShort(cols, false);
    for (int i = 0; i < shortCols; ++i) {
        isShort[i] = true;
    }
    qDebug() << "isShort (короткие столбцы):" << isShort;

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

        qDebug() << "Столбец" << colIdx << "(порядок" << readOrder << ") высота:" << colHeight;

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
    qDebug() << "\nЗаполненная таблица:\n" << tableDisplay;

    steps.append(CipherStep(steps.size() + 1, QChar(),
        tableToString(table), QStringLiteral(u"Таблица, заполненная по столбцам")));

    // Шаг 6: Чтение таблицы по строкам в порядке rowOrder
    QString decrypted;

    // Создаем карту порядка строк: позиция -> индекс строки
    QVector<int> rowIndexByOrder(rows);
    for (int i = 0; i < rows; ++i) {
        rowIndexByOrder[normalizedRowOrder[i] - 1] = i;
    }
    qDebug() << "rowIndexByOrder:" << rowIndexByOrder;

    for (int orderNum = 1; orderNum <= rows; ++orderNum) {
        int rowIdx = rowIndexByOrder[orderNum - 1];

        // Определяем направление чтения (используем writeDirections)
        Direction direction = LEFT_TO_RIGHT;
        if (rowIdx < writeDirections.size()) {
            direction = writeDirections[rowIdx];
        } else if (!writeDirections.isEmpty()) {
            direction = writeDirections.last();
        }

        qDebug() << "\nЧтение строки" << rowIdx << "(порядок записи" << orderNum
                 << ") направление:" << (direction == LEFT_TO_RIGHT ? "→" : "←");

        QString rowChars;

        if (direction == LEFT_TO_RIGHT) {
            for (int j = 0; j < cols; ++j) {
                if (!table[rowIdx][j].isNull()) {
                    decrypted += table[rowIdx][j];
                    rowChars += table[rowIdx][j];
                    qDebug() << "  read [" << rowIdx << "][" << j << "] =" << table[rowIdx][j];
                }
            }
        } else {
            for (int j = cols - 1; j >= 0; --j) {
                if (!table[rowIdx][j].isNull()) {
                    decrypted += table[rowIdx][j];
                    rowChars += table[rowIdx][j];
                    qDebug() << "  read [" << rowIdx << "][" << j << "] =" << table[rowIdx][j];
                }
            }
        }

        qDebug() << "  результат:" << rowChars;

        if (!rowChars.isEmpty()) {
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
    }

    // Шаг 7: Итоговый результат
    qDebug() << "\n=== ИТОГОВЫЙ РАСШИФРОВАННЫЙ ТЕКСТ ===";
    qDebug() << decrypted;

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

                qDebug() << "ColumnTranspositionCipher: расширенный виджет создан";
            }
        );

        qDebug() << "ColumnTranspositionCipher зарегистрирован";
    }
};

// Статический регистратор
static ColumnTranspositionCipherRegister columnTranspositionCipherRegister;
