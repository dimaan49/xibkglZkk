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

// ==================== РЕГИСТРАЦИЯ В ФАБРИКЕ ====================

class ColumnTranspositionCipherRegister
{
public:
    ColumnTranspositionCipherRegister()
    {
        CipherFactory::instance().registerCipher(
            "columntransposition",
            "Вертикальная перестановка",
            []() -> CipherInterface* { return new ColumnTranspositionCipher(); }
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
