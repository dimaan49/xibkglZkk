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
    QVector<int> order;

    if (key.isEmpty()) {
        errorMessage = "Ключ не может быть пустым";
        return order;
    }

    QString cleanKey = CipherUtils::filterAlphabetOnly(key.toUpper(), RUSSIAN_ALPHABET);

    if (cleanKey.isEmpty()) {
        errorMessage = "Ключ должен содержать хотя бы одну букву русского алфавита";
        return order;
    }

    if (cleanKey.length() != columnCount) {
        errorMessage = QString("Длина ключа (%1) не соответствует количеству столбцов (%2)")
                              .arg(cleanKey.length()).arg(columnCount);
        return order;
    }

    QVector<QPair<QChar, int>> letters;
    for (int i = 0; i < cleanKey.length(); ++i) {
        letters.append(qMakePair(cleanKey[i], i));
    }

    std::stable_sort(letters.begin(), letters.end(),
        [](const QPair<QChar, int>& a, const QPair<QChar, int>& b) {
            return a.first < b.first;
        });

    QVector<int> tempOrder(columnCount);
    for (int i = 0; i < letters.size(); ++i) {
        int originalPos = letters[i].second;
        tempOrder[originalPos] = i + 1;
    }

    return tempOrder;
}

CipherResult ColumnTranspositionCipher::encrypt(const QString& text, const QVariantMap& params)
{
    qDebug() << "\n=== ColumnTranspositionCipher::encrypt ===";

    QString cleanText = CipherUtils::filterAlphabetOnly(text, RUSSIAN_ALPHABET);

    // Получаем ключ из параметров
    QString key = params.value("key", "").toString();
    qDebug() << "Key from params:" << key;

    // Получаем размеры из расширенных параметров
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

    // Получаем направления записи из расширенных параметров
    QVector<Direction> writeDirections;
    if (params.contains("writeDirections")) {
        QVariantList dirList = params.value("writeDirections").toList();
        for (const QVariant& v : dirList) {
            writeDirections.append(static_cast<Direction>(v.toInt()));
        }
    } else {
        writeDirections = getDefaultWriteDirections(rows);
    }

    // Направления чтения - все сверху вниз
    QVector<Direction> readDirections(cols, TOP_TO_BOTTOM);

    // Порядок строк из расширенных параметров
    QVector<int> rowOrder;
    if (params.contains("rowOrder")) {
        QVariantList orderList = params.value("rowOrder").toList();
        for (const QVariant& v : orderList) {
            rowOrder.append(v.toInt());
        }
    } else {
        for (int i = 1; i <= rows; ++i) {
            rowOrder.append(i);
        }
    }

    return encryptImpl(cleanText, rows, cols, writeDirections, readDirections,
                      rowOrder, columnOrder);
}


// Добавьте этот метод в класс ColumnTranspositionCipher (в файле .cpp)

CipherResult ColumnTranspositionCipher::decrypt(const QString& text, const QVariantMap& params)
{
    qDebug() << "\n=== ColumnTranspositionCipher::decrypt ===";

    QString cleanText = CipherUtils::filterAlphabetOnly(text, RUSSIAN_ALPHABET);

    // Получаем ключ из параметров
    QString key = params.value("key", "").toString();
    qDebug() << "Key from params:" << key;

    // Получаем размеры из расширенных параметров
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

    // Для дешифрования нам нужно знать, как заполнялась таблица
    // Получаем направления записи из расширенных параметров
    QVector<Direction> writeDirections;
    if (params.contains("writeDirections")) {
        QVariantList dirList = params.value("writeDirections").toList();
        for (const QVariant& v : dirList) {
            writeDirections.append(static_cast<Direction>(v.toInt()));
        }
    } else {
        writeDirections = getDefaultWriteDirections(rows);
    }

    // Для дешифрования чтение будет обратным направлению записи при шифровании
    // Направления чтения - все сверху вниз (так как при шифровании читали столбцы сверху вниз)
    QVector<Direction> readDirections(cols, TOP_TO_BOTTOM);

    // Порядок строк из расширенных параметров
    QVector<int> rowOrder;
    if (params.contains("rowOrder")) {
        QVariantList orderList = params.value("rowOrder").toList();
        for (const QVariant& v : orderList) {
            rowOrder.append(v.toInt());
        }
    } else {
        for (int i = 1; i <= rows; ++i) {
            rowOrder.append(i);
        }
    }

    // Для дешифрования нам нужно выполнить обратные операции:
    // 1. Сначала заполнить таблицу по столбцам в порядке, определяемом ключом
    // 2. Затем прочитать по строкам с учетом направлений записи

    return decryptImpl(cleanText, rows, cols, writeDirections, readDirections,
                      rowOrder, columnOrder);
}

// Добавьте этот вспомогательный метод в класс ColumnTranspositionCipher

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
    steps.append(CipherStep(1, QChar(), cleanText, QStringLiteral(u"Очищенный текст (шифртекст)")));

    // Шаг 2: Информация о размере таблицы
    steps.append(CipherStep(2, QChar(),
        QString("%1×%2").arg(rows).arg(cols),
        QStringLiteral(u"Размер таблицы")));

    // Нормализуем порядки
    QVector<int> normalizedRowOrder = normalizeOrder(rowOrder, rows, "строк");
    QVector<int> normalizedColumnOrder = normalizeOrder(columnOrder, cols, "столбцов");

    // Шаг 3: Создаем пустую таблицу нужного размера
    std::vector<std::vector<QChar>> table(rows, std::vector<QChar>(cols, QChar()));
    steps.append(CipherStep(3, QChar(),
        tableToString(table), QStringLiteral(u"Пустая таблица %1×%2").arg(rows).arg(cols)));

    // Шаг 4: Заполняем таблицу по столбцам в порядке, определенном ключом
    // Для вертикальной перестановки при шифровании читали столбцы в порядке columnOrder
    // Значит, при дешифровании нужно заполнять столбцы в этом же порядке
    int textIndex = 0;

    // Создаем карту соответствия порядка столбцов их индексам
    QVector<int> colIndexByOrder(cols);
    for (int i = 0; i < cols; ++i) {
        colIndexByOrder[normalizedColumnOrder[i] - 1] = i;
    }

    QString fillInfo;
    for (int orderNum = 1; orderNum <= cols && textIndex < cleanText.length(); ++orderNum) {
        int colIdx = colIndexByOrder[orderNum - 1];
        QString columnChars;

        // Заполняем столбец сверху вниз (так как при шифровании читали сверху вниз)
        for (int i = 0; i < rows && textIndex < cleanText.length(); ++i) {
            // Проверяем, должна ли быть в этой ячейке буква (учитываем неполный последний столбец)
            // В таблице могут быть пустые ячейки, если текст короче размера таблицы
            int cellIndex = i * cols + colIdx;
            if (cellIndex < cleanText.length()) {
                table[i][colIdx] = cleanText[textIndex];
                columnChars += cleanText[textIndex];
                textIndex++;
            }
        }

        if (!columnChars.isEmpty()) {
            steps.append(CipherStep(
                steps.size() + 1,
                QChar(),
                columnChars,
                QString("Заполнение столбца %1 (порядок %2): сверху вниз")
                    .arg(colIdx + 1)
                    .arg(orderNum)
            ));
        }
    }

    // Шаг 5: Отображение заполненной таблицы
    steps.append(CipherStep(steps.size() + 1, QChar(),
        tableToString(table), QStringLiteral(u"Таблица, заполненная по столбцам")));

    // Шаг 6: Чтение таблицы по строкам с учетом направлений записи
    QString decrypted;
    QVector<CipherStep> readSteps;

    // Создаем карту порядка строк
    QVector<int> rowIndexByOrder(rows);
    for (int i = 0; i < rows; ++i) {
        rowIndexByOrder[normalizedRowOrder[i] - 1] = i;
    }

    for (int orderNum = 1; orderNum <= rows; ++orderNum) {
        int rowIdx = rowIndexByOrder[orderNum - 1];

        // Определяем направление чтения для текущей строки
        Direction direction;
        if (rowIdx < writeDirections.size()) {
            direction = writeDirections[rowIdx];
        } else if (!writeDirections.isEmpty()) {
            direction = writeDirections.last();
        } else {
            direction = LEFT_TO_RIGHT;
        }

        QString rowChars;

        // Читаем строку в соответствии с направлением
        if (direction == LEFT_TO_RIGHT) {
            for (int j = 0; j < cols; ++j) {
                if (!table[rowIdx][j].isNull()) {
                    decrypted += table[rowIdx][j];
                    rowChars += table[rowIdx][j];
                }
            }
        } else { // RIGHT_TO_LEFT
            for (int j = cols - 1; j >= 0; --j) {
                if (!table[rowIdx][j].isNull()) {
                    decrypted += table[rowIdx][j];
                    rowChars += table[rowIdx][j];
                }
            }
        }

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
    steps.append(CipherStep(steps.size() + 1, QChar(),
        decrypted, QStringLiteral(u"Итоговый расшифрованный текст")));

    // Перенумеровываем шаги
    for (int i = 0; i < steps.size(); ++i) {
        steps[i].index = i + 1;
    }

    // Формируем описание
    QString description = QStringLiteral(u"ColumnTranspositionCipher - дешифрование\n")
                        + QStringLiteral(u"Размер таблицы: %1×%2\n").arg(rows).arg(cols)
                        + QStringLiteral(u"Ключ определяет порядок столбцов\n");

    if (!normalizedRowOrder.isEmpty()) {
        description += QStringLiteral(u"Порядок строк: ");
        for (int i = 0; i < normalizedRowOrder.size(); ++i) {
            if (i > 0) description += ", ";
            description += QString::number(normalizedRowOrder[i]);
        }
        description += "\n";
    }

    return CipherResult(decrypted, steps, description, name() + " (дешифрование)", false);
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
            "columntransposition",
            // Основной виджет - только поле для ключа
            [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
             // Базовые параметры - поле для ключа
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

                // Можно добавить поясняющий текст отдельно
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

                // Подключаем сигнал изменения параметров
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
