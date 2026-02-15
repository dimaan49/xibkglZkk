#include "playfair.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QDebug>
#include <QRegularExpression>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>
#include <QGridLayout>
#include <QGroupBox>

// Определение статических констант с использованием QStringLiteral
const QChar PlayfairCipher::DEFAULT_FILLER = QChar(0x0425); // Явно задаём Unicode код для 'Х'
const QString PlayfairCipher::ALPHABET_5x6 = QStringLiteral(u"АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЬЫЭЮЯ");
const QString PlayfairCipher::ALPHABET_4x8 = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

PlayfairCipher::PlayfairCipher() {}

QString PlayfairCipher::name() const
{
    return QStringLiteral(u"Шифр Плейфера");
}

QString PlayfairCipher::description() const
{
    return QStringLiteral(u"Биграммный шифр, использующий таблицу 5×6 или 4×8, "
                         "заполненную по слову-лозунгу. Шифрование происходит по "
                         "правилам прямоугольника, строки или столбца.");
}

QString PlayfairCipher::getAlphabet(MatrixSize size) const
{
    return (size == Size5x6) ? ALPHABET_5x6 : ALPHABET_4x8;
}

QChar PlayfairCipher::normalizeChar(const QChar& ch, MatrixSize size) const
{
    if (size == Size5x6) {
        if (ch == QChar('Ё') || ch == QChar(0x0401)) return QChar('Е');
        if (ch == QChar('Й') || ch == QChar(0x0419)) return QChar('И');
        if (ch == QChar('Ъ') || ch == QChar(0x042A)) return QChar('Ь');
    } else { // Size4x8
        if (ch == QChar('Ё') || ch == QChar(0x0401)) return QChar('Е');
    }
    return ch;
}

QString PlayfairCipher::prepareText(const QString& text, MatrixSize size, QChar filler, bool forEncrypt)
{
    QString result;
    QString alphabet = getAlphabet(size);

    // Фильтруем и нормализуем текст
    for (const QChar& ch : text.toUpper()) {
        QChar normalized = normalizeChar(ch, size);
        if (alphabet.contains(normalized)) {
            result.append(normalized);
        }
    }

    if (forEncrypt && !result.isEmpty()) {
        // Разбиваем на биграммы и обрабатываем повторяющиеся буквы
        QStringList bigrams = splitIntoBigrams(result, filler);
        result = bigrams.join("");
    }

    return result;
}

QStringList PlayfairCipher::splitIntoBigrams(const QString& text, QChar filler)
{
    QStringList bigrams;
    QString processed;
    processed.reserve(text.length() * 2);

    int i = 0;
    while (i < text.length()) {
        if (i + 1 >= text.length()) {
            // Последний символ - добавляем фиктивную букву
            processed.append(text[i]);
            processed.append(filler);
            i++;
        }
        else if (text[i] == text[i + 1]) {
            // Две одинаковые буквы подряд
            processed.append(text[i]);  // первая буква
            processed.append(filler);    // фиктивная буква между ними
            i++; // переходим ко второй букве
        }
        else {
            // Нормальная биграмма
            processed.append(text[i]);     // первая буква
            processed.append(text[i + 1]); // вторая буква
            i += 2;
        }
    }

    // Разбиваем на биграммы
    for (i = 0; i < processed.length(); i += 2) {
        if (i + 1 < processed.length()) {
            bigrams.append(processed.mid(i, 2));
        }
    }

    return bigrams;
}

QVector<QVector<QChar>> PlayfairCipher::createTable(const QString& slogan, MatrixSize size)
{
    int rows = (size == Size5x6) ? 5 : 4;
    int cols = (size == Size5x6) ? 6 : 8;

    QString alphabet = getAlphabet(size);

    QVector<QVector<QChar>> table(rows, QVector<QChar>(cols));
    QString used;

    // Сначала добавляем буквы из лозунга (без повторов)
    QString upperSlogan = slogan.toUpper();
    for (const QChar& ch : upperSlogan) {
        QChar normalized = normalizeChar(ch, size);
        if (alphabet.contains(normalized) && !used.contains(normalized)) {
            used.append(normalized);
        }
    }

    // Затем добавляем остальные буквы алфавита по порядку
    for (const QChar& ch : alphabet) {
        if (!used.contains(ch)) {
            used.append(ch);
        }
    }

    // Заполняем таблицу
    int index = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (index < used.length()) {
                table[i][j] = used[index++];
            }
        }
    }

    return table;
}

QVector<QVector<QChar>> PlayfairCipher::generateTable(const QString& slogan, MatrixSize size) const
{
    return const_cast<PlayfairCipher*>(this)->createTable(slogan, size);
}

PlayfairCipher::Position PlayfairCipher::findPosition(const QVector<QVector<QChar>>& table, QChar ch) const
{
    for (int i = 0; i < table.size(); i++) {
        for (int j = 0; j < table[i].size(); j++) {
            if (table[i][j] == ch) {
                return Position(i, j);
            }
        }
    }
    return Position(-1, -1);
}


QString PlayfairCipher::processBigram(const QVector<QVector<QChar>>& table, const QString& bigram, bool encrypt)
{
    if (bigram.length() != 2) return bigram;

    Position pos1 = findPosition(table, bigram[0]);
    Position pos2 = findPosition(table, bigram[1]);

    if (!pos1.isValid() || !pos2.isValid()) {
        return bigram;
    }

    int rows = table.size();
    int cols = table[0].size();

    if (pos1.row == pos2.row) {
        // Одна строка
        int col1, col2;
        if (encrypt) {
            col1 = (pos1.col + 1) % cols;
            col2 = (pos2.col + 1) % cols;
        } else {
            col1 = (pos1.col - 1 + cols) % cols;
            col2 = (pos2.col - 1 + cols) % cols;
        }
        return QString(table[pos1.row][col1]) + QString(table[pos2.row][col2]);
    }
    else if (pos1.col == pos2.col) {
        // Один столбец
        int row1, row2;
        if (encrypt) {
            row1 = (pos1.row + 1) % rows;
            row2 = (pos2.row + 1) % rows;
        } else {
            row1 = (pos1.row - 1 + rows) % rows;
            row2 = (pos2.row - 1 + rows) % rows;
        }
        return QString(table[row1][pos1.col]) + QString(table[row2][pos2.col]);
    }
    else {
        // Прямоугольник - меняем столбцы
        return QString(table[pos1.row][pos2.col]) + QString(table[pos2.row][pos1.col]);
    }
}

QString PlayfairCipher::formatResult(const QStringList& bigrams)
{
    return bigrams.join(' ');
}

QStringList PlayfairCipher::parseEncryptedText(const QString& text)
{
    QStringList result;
    QString cleaned = text.toUpper();
    cleaned.remove(' ');
    cleaned.remove('\t');
    cleaned.remove('\n');

    for (int i = 0; i < cleaned.length(); i += 2) {
        if (i + 1 < cleaned.length()) {
            result.append(cleaned.mid(i, 2));
        }
    }

    return result;
}

bool PlayfairCipher::isFillerAndRemovable(const QString& text, int index, QChar filler) const
{
    if (index >= text.length() || text[index] != filler) return false;

    // Проверяем, является ли эта буква фиктивной
    if (index == text.length() - 1) {
        // Последняя буква
        return true;
    }

    if (index > 0 && index < text.length() - 1 && text[index - 1] == text[index + 1]) {
        // Между одинаковыми буквами
        return true;
    }

    // Проверка для случая, когда фиктивная буква вставлена между одинаковыми
    // и после неё идёт такая же буква
    if (index < text.length() - 1 && index > 0 &&
        text[index - 1] == text[index + 1] &&
        text[index] == filler) {
        return true;
    }

    return false;
}

// Вспомогательная функция для безопасного получения filler из параметров
QChar getFillerFromParams(const QVariantMap& params, const QChar& defaultValue)
{
    if (!params.contains("filler")) {
        return defaultValue;
    }

    QVariant fillerVar = params["filler"];

    // Если это строка, берём первый символ
    if (fillerVar.type() == QVariant::String || fillerVar.type() == QVariant::ByteArray) {
        QString fillerStr = fillerVar.toString().trimmed().toUpper();
        if (!fillerStr.isEmpty()) {
            // Проверяем, не латиница ли это 'X'
            if (fillerStr[0] == QLatin1Char('X') || fillerStr[0] == QLatin1Char('x')) {
                return QChar(0x0425); // Кириллическая Х
            }
            return fillerStr[0];
        }
    }
    // Если это QChar, проверяем и нормализуем
    else if (fillerVar.type() == QVariant::Char) {
        QChar ch = fillerVar.toChar().toUpper();
        if (ch == QLatin1Char('X')) {
            return QChar(0x0425); // Кириллическая Х
        }
        return ch;
    }

    return defaultValue;
}

CipherResult PlayfairCipher::encrypt(const QString& text, const QVariantMap& params)
{
    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), QStringLiteral("Начало шифрования"), QStringLiteral("Инициализация")));

    try {
        // Шаг 1: Получение параметров
        if (!params.contains("slogan") || !params.contains("matrixSize")) {
            steps.append(CipherStep(1, QChar(), QStringLiteral("Ошибка: не заданы параметры шифрования"), QStringLiteral("Проверка параметров")));
            return CipherResult("", steps, QStringLiteral("Шифр Плейфера (ошибка)"), name(), true);
        }

        QString slogan = params["slogan"].toString();
        MatrixSize size = static_cast<MatrixSize>(params["matrixSize"].toInt());

        // Безопасное получение filler
        QChar filler = getFillerFromParams(params, DEFAULT_FILLER);

        // Формируем строку параметров безопасным способом
        QString sizeStr = (size == Size5x6) ? QStringLiteral("5×6") : QStringLiteral("4×8");
        QString paramMsg = QStringLiteral("Параметры: размер=") + sizeStr +
                          QStringLiteral(", лозунг='") + slogan +
                          QStringLiteral("', фиктивная буква='") + QString(filler) +
                          QStringLiteral("'");

        steps.append(CipherStep(1, QChar(), paramMsg, QStringLiteral("Загрузка параметров")));

        // Шаг 2: Создание таблицы
        QVector<QVector<QChar>> table = createTable(slogan, size);

        QString tableDisplay;
        for (int i = 0; i < table.size(); i++) {
            tableDisplay += QStringLiteral("|");
            for (int j = 0; j < table[i].size(); j++) {
                tableDisplay += QStringLiteral(" ") + QString(table[i][j]) + QStringLiteral(" |");
            }
            tableDisplay += QStringLiteral("\n");
        }

        steps.append(CipherStep(2, QChar(),
            QString(QStringLiteral("Создана таблица %1x%2 по лозунгу:\n%3"))
                .arg(table.size()).arg(table[0].size()).arg(tableDisplay),
            QStringLiteral("Генерация таблицы")));

        // Шаг 3: Подготовка текста
        QString preparedText = prepareText(text, size, filler, true);

        if (preparedText.isEmpty()) {
            steps.append(CipherStep(3, QChar(), QStringLiteral("Ошибка: текст не содержит допустимых символов"), QStringLiteral("Подготовка текста")));
            return CipherResult("", steps, QStringLiteral("Шифр Плейфера (ошибка)"), name(), true);
        }

        steps.append(CipherStep(3, QChar(),
            QString(QStringLiteral("Исходный текст после обработки: %1")).arg(preparedText),
            QStringLiteral("Подготовка текста")));

        // Шаг 4: Разбивка на биграммы
        QStringList bigrams = splitIntoBigrams(preparedText, filler);

        QString bigramsStr;
        for (int i = 0; i < bigrams.size(); i++) {
            bigramsStr += bigrams[i];
            if (i < bigrams.size() - 1) bigramsStr += QStringLiteral(" ");
        }

        steps.append(CipherStep(4, QChar(),
            QString(QStringLiteral("Разбито на %1 биграмм: %2")).arg(bigrams.size()).arg(bigramsStr),
            QStringLiteral("Разбивка на биграммы")));

        // Шаг 5: Шифрование каждой биграммы
        QStringList encryptedBigrams;

        for (int i = 0; i < bigrams.size(); i++) {
            const QString& bigram = bigrams[i];

            steps.append(CipherStep(5 + i * 2, QChar(),
                QString(QStringLiteral("Биграмма %1: '%2'")).arg(i + 1).arg(bigram),
                QString(QStringLiteral("Обработка биграммы %1")).arg(i + 1)));

            Position pos1 = findPosition(table, bigram[0]);
            Position pos2 = findPosition(table, bigram[1]);

            QString rule;
            if (pos1.row == pos2.row) {
                rule = QStringLiteral("одна строка → сдвиг вправо");
            } else if (pos1.col == pos2.col) {
                rule = QStringLiteral("один столбец → сдвиг вниз");
            } else {
                rule = QStringLiteral("прямоугольник → обмен столбцами");
            }

            QString encrypted = processBigram(table, bigram, true);
            encryptedBigrams.append(encrypted);

            steps.append(CipherStep(6 + i * 2, QChar(),
                QString(QStringLiteral("→ '%1' (%2)")).arg(encrypted).arg(rule),
                QString(QStringLiteral("Результат биграммы %1")).arg(i + 1)));
        }

        // Шаг 6: Формирование результата
        QString result = formatResult(encryptedBigrams);

        steps.append(CipherStep(5 + bigrams.size() * 2, QChar(),
            QString(QStringLiteral("Зашифрованный текст: %1")).arg(result),
            QStringLiteral("Формирование результата")));

        // Формируем описание
        QString description = QStringLiteral("Шифр Плейфера\n"
                                    "════════════════════════════════════════\n"
                                    "Размер таблицы: ") +
                                    (size == Size5x6 ? QStringLiteral("5x6") : QStringLiteral("4x8")) +
                                    QStringLiteral("\nСлово-лозунг: ") + slogan +
                                    QStringLiteral("\nФиктивная буква: ") + QString(filler) +
                                    QStringLiteral("\nИсходный текст: ") + QString::number(preparedText.length()) +
                                    QStringLiteral(" символов\nБиграмм: ") + QString::number(bigrams.size());

        return CipherResult(result, steps, description, name(), true);

    } catch (const std::exception& e) {
        steps.append(CipherStep(99, QChar(),
            QString(QStringLiteral("Исключение: %1")).arg(e.what()),
            QStringLiteral("Ошибка выполнения")));
        return CipherResult("", steps, QStringLiteral("Шифр Плейфера (ошибка)"), name(), true);
    }
}

CipherResult PlayfairCipher::decrypt(const QString& text, const QVariantMap& params)
{
    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), QStringLiteral("Начало дешифрования"), QStringLiteral("Инициализация")));

    try {
        // Шаг 1: Получение параметров
        if (!params.contains("slogan") || !params.contains("matrixSize")) {
            steps.append(CipherStep(1, QChar(), QStringLiteral("Ошибка: не заданы параметры дешифрования"), QStringLiteral("Проверка параметров")));
            return CipherResult("", steps, QStringLiteral("Шифр Плейфера (дешифрование, ошибка)"), name() + QStringLiteral(" (дешифрование)"), false);
        }

        QString slogan = params["slogan"].toString();
        MatrixSize size = static_cast<MatrixSize>(params["matrixSize"].toInt());

        // Безопасное получение filler
        QChar filler = getFillerFromParams(params, DEFAULT_FILLER);

        QString sizeStr = (size == Size5x6) ? QStringLiteral("5×6") : QStringLiteral("4×8");
        QString paramMsg = QStringLiteral("Параметры: размер=") + sizeStr +
                          QStringLiteral(", лозунг='") + slogan +
                          QStringLiteral("', фиктивная буква='") + QString(filler) +
                          QStringLiteral("'");

        steps.append(CipherStep(1, QChar(), paramMsg, QStringLiteral("Загрузка параметров")));

        // Шаг 2: Создание таблицы
        QVector<QVector<QChar>> table = createTable(slogan, size);

        QString tableDisplay;
        for (int i = 0; i < table.size(); i++) {
            tableDisplay += QStringLiteral("|");
            for (int j = 0; j < table[i].size(); j++) {
                tableDisplay += QStringLiteral(" ") + QString(table[i][j]) + QStringLiteral(" |");
            }
            tableDisplay += QStringLiteral("\n");
        }

        steps.append(CipherStep(2, QChar(),
            QString(QStringLiteral("Создана таблица %1x%2 по лозунгу:\n%3"))
                .arg(table.size()).arg(table[0].size()).arg(tableDisplay),
            QStringLiteral("Генерация таблицы")));

        // Шаг 3: Разбор зашифрованного текста на биграммы
        QStringList encryptedBigrams = parseEncryptedText(text);

        if (encryptedBigrams.isEmpty()) {
            steps.append(CipherStep(3, QChar(), QStringLiteral("Ошибка: не удалось разобрать зашифрованный текст"), QStringLiteral("Разбор биграмм")));
            return CipherResult("", steps, QStringLiteral("Шифр Плейфера (дешифрование, ошибка)"), name() + QStringLiteral(" (дешифрование)"), false);
        }

        QString bigramsStr = encryptedBigrams.join(' ');

        steps.append(CipherStep(3, QChar(),
            QString(QStringLiteral("Зашифрованный текст разбит на %1 биграмм: %2"))
                .arg(encryptedBigrams.size()).arg(bigramsStr),
            QStringLiteral("Разбор биграмм")));

        // Шаг 4: Дешифрование каждой биграммы
        QStringList decryptedBigrams;

        for (int i = 0; i < encryptedBigrams.size(); i++) {
            const QString& bigram = encryptedBigrams[i];

            steps.append(CipherStep(4 + i * 2, QChar(),
                QString(QStringLiteral("Биграмма %1: '%2'")).arg(i + 1).arg(bigram),
                QString(QStringLiteral("Обработка биграммы %1")).arg(i + 1)));

            Position pos1 = findPosition(table, bigram[0]);
            Position pos2 = findPosition(table, bigram[1]);

            QString rule;
            if (pos1.row == pos2.row) {
                rule = QStringLiteral("одна строка → сдвиг влево");
            } else if (pos1.col == pos2.col) {
                rule = QStringLiteral("один столбец → сдвиг вверх");
            } else {
                rule = QStringLiteral("прямоугольник → обмен столбцами");
            }

            QString decrypted = processBigram(table, bigram, false);
            decryptedBigrams.append(decrypted);

            steps.append(CipherStep(5 + i * 2, QChar(),
                QString(QStringLiteral("→ '%1' (%2)")).arg(decrypted).arg(rule),
                QString(QStringLiteral("Результат биграммы %1")).arg(i + 1)));
        }

        // Шаг 5: Объединение результата
        QString combined = decryptedBigrams.join("");

        // Убираем фиктивные буквы
        QString result;
        for (int i = 0; i < combined.length(); i++) {
            if (!isFillerAndRemovable(combined, i, filler)) {
                result.append(combined[i]);
            }
        }

        steps.append(CipherStep(4 + encryptedBigrams.size() * 2, QChar(),
            QString(QStringLiteral("Расшифрованный текст (после удаления фиктивных букв): %1")).arg(result),
            QStringLiteral("Формирование результата")));

        // Формируем описание
        QString description = QStringLiteral("Дешифрование шифра Плейфера\n"
                                    "════════════════════════════════════════\n"
                                    "Размер таблицы: ") +
                                    (size == Size5x6 ? QStringLiteral("5x6") : QStringLiteral("4x8")) +
                                    QStringLiteral("\nСлово-лозунг: ") + slogan +
                                    QStringLiteral("\nФиктивная буква: ") + QString(filler) +
                                    QStringLiteral("\nБиграмм в шифртексте: ") + QString::number(encryptedBigrams.size()) +
                                    QStringLiteral("\nПолучено символов: ") + QString::number(result.length());

        return CipherResult(result, steps, description, name() + QStringLiteral(" (дешифрование)"), false);

    } catch (const std::exception& e) {
        steps.append(CipherStep(99, QChar(),
            QString(QStringLiteral("Исключение: %1")).arg(e.what()),
            QStringLiteral("Ошибка выполнения")));
        return CipherResult("", steps, QStringLiteral("Шифр Плейфера (дешифрование, ошибка)"), name() + QStringLiteral(" (дешифрование)"), false);
    }
}

// Регистратор виджетов
PlayfairCipherRegister::PlayfairCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "playfair",
        "Шифр Плейфера",
        []() -> CipherInterface* { return new PlayfairCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "playfair",
        // Основные виджеты
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QLabel* infoLabel = new QLabel(QStringLiteral("Ключ: слово-лозунг для заполнения таблицы 5×6 или 4×8"), parent);
            infoLabel->setStyleSheet(QStringLiteral("color: #7f8c8d; font-style: italic;"));
            infoLabel->setWordWrap(true);
            layout->addWidget(infoLabel);
        },
        // Расширенные виджеты
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QHBoxLayout* mainLayout = new QHBoxLayout();
            layout->addLayout(mainLayout);

            QVBoxLayout* leftPanel = new QVBoxLayout();
            mainLayout->addLayout(leftPanel, 1);

            QVBoxLayout* rightPanel = new QVBoxLayout();
            mainLayout->addLayout(rightPanel, 2);

            // Левая панель - настройки
            QGroupBox* sizeGroup = new QGroupBox(QStringLiteral("Размерность таблицы"), parent);
            QVBoxLayout* sizeLayout = new QVBoxLayout(sizeGroup);

            QComboBox* sizeCombo = new QComboBox(parent);
            sizeCombo->setObjectName(QStringLiteral("matrixSize"));
            sizeCombo->addItem(QStringLiteral("5 × 6 (30 букв, исключаются Ё, Й, Ъ)"), 0);
            sizeCombo->addItem(QStringLiteral("4 × 8 (32 буквы, исключается только Ё)"), 1);
            sizeLayout->addWidget(sizeCombo);

            leftPanel->addWidget(sizeGroup);
            widgets[QStringLiteral("matrixSize")] = sizeCombo;

            QGroupBox* keyGroup = new QGroupBox(QStringLiteral("Ключ шифрования"), parent);
            QVBoxLayout* keyLayout = new QVBoxLayout(keyGroup);

            QLabel* sloganLabel = new QLabel(QStringLiteral("Слово-лозунг:"), parent);
            keyLayout->addWidget(sloganLabel);

            QLineEdit* sloganEdit = new QLineEdit(parent);
            sloganEdit->setObjectName(QStringLiteral("slogan"));
            sloganEdit->setPlaceholderText(QStringLiteral("Введите слово-лозунг, например: РЕСПУБЛИКА"));
            sloganEdit->setText(QStringLiteral("РЕСПУБЛИКА"));
            keyLayout->addWidget(sloganEdit);
            widgets[QStringLiteral("slogan")] = sloganEdit;

            QLabel* fillerLabel = new QLabel(QStringLiteral("Фиктивная буква (для повторяющихся):"), parent);
            fillerLabel->setStyleSheet(QStringLiteral("margin-top: 10px;"));
            keyLayout->addWidget(fillerLabel);

            QLineEdit* fillerEdit = new QLineEdit(parent);
            fillerEdit->setObjectName(QStringLiteral("filler"));
            fillerEdit->setPlaceholderText(QStringLiteral("Х"));
            fillerEdit->setText(QStringLiteral("Х"));
            fillerEdit->setMaxLength(1);

            // Убеждаемся, что это кириллица
            QFont font = fillerEdit->font();
            font.setFamily(QStringLiteral("Arial"));
            fillerEdit->setFont(font);

            keyLayout->addWidget(fillerEdit);
            widgets[QStringLiteral("filler")] = fillerEdit;

            leftPanel->addWidget(keyGroup);

            QPushButton* generateButton = new QPushButton(QStringLiteral("Сгенерировать таблицу"), parent);
            generateButton->setObjectName(QStringLiteral("generateTableButton"));
            generateButton->setStyleSheet(QStringLiteral("QPushButton { background-color: #3498db; color: white; padding: 8px; margin-top: 10px; }"));
            leftPanel->addWidget(generateButton);

            QLabel* infoLabel = new QLabel(parent);
            infoLabel->setObjectName(QStringLiteral("infoLabel"));
            infoLabel->setWordWrap(true);
            infoLabel->setText(QStringLiteral("✓ Введите слово-лозунг и нажмите кнопку для генерации таблицы"));
            infoLabel->setStyleSheet(QStringLiteral("color: #7f8c8d; font-style: italic; margin-top: 10px;"));
            leftPanel->addWidget(infoLabel);

            QLabel* exampleLabel = new QLabel(QStringLiteral("Быстрые примеры:"), parent);
            exampleLabel->setStyleSheet(QStringLiteral("font-weight: bold; margin-top: 15px;"));
            leftPanel->addWidget(exampleLabel);

            QHBoxLayout* exampleLayout = new QHBoxLayout();

            QPushButton* example1Button = new QPushButton(QStringLiteral("5x6: РЕСПУБЛИКА"), parent);
            example1Button->setObjectName(QStringLiteral("example1Button"));
            example1Button->setStyleSheet(QStringLiteral("QPushButton { background-color: #27ae60; color: white; }"));
            exampleLayout->addWidget(example1Button);

            QPushButton* example2Button = new QPushButton(QStringLiteral("4x8: ЛОЗУНГ"), parent);
            example2Button->setObjectName(QStringLiteral("example2Button"));
            example2Button->setStyleSheet(QStringLiteral("QPushButton { background-color: #27ae60; color: white; }"));
            exampleLayout->addWidget(example2Button);

            leftPanel->addLayout(exampleLayout);
            leftPanel->addStretch();

            // Правая панель - таблица
            QLabel* tableTitleLabel = new QLabel(QStringLiteral("Сгенерированная таблица:"), parent);
            tableTitleLabel->setStyleSheet(QStringLiteral("font-weight: bold; font-size: 14px; margin-bottom: 10px;"));
            rightPanel->addWidget(tableTitleLabel);

            QFrame* tableFrame = new QFrame(parent);
            tableFrame->setFrameStyle(QFrame::Box);
            tableFrame->setLineWidth(2);
            tableFrame->setStyleSheet(QStringLiteral("QFrame { background-color: #2c3e50; border-radius: 5px; }"));

            QVBoxLayout* frameLayout = new QVBoxLayout(tableFrame);
            frameLayout->setContentsMargins(15, 15, 15, 15);

            QTableWidget* tableWidget = new QTableWidget(parent);
            tableWidget->setObjectName(QStringLiteral("tableDisplay"));
            tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
            tableWidget->horizontalHeader()->setVisible(false);
            tableWidget->verticalHeader()->setVisible(false);
            tableWidget->setStyleSheet(QStringLiteral(
                "QTableWidget { background-color: #ecf0f1; gridline-color: #34495e; }"
                "QTableWidget::item { padding: 5px; }"
            ));

            frameLayout->addWidget(tableWidget);
            rightPanel->addWidget(tableFrame);

            QLabel* statsLabel = new QLabel(parent);
            statsLabel->setObjectName(QStringLiteral("statsLabel"));
            statsLabel->setStyleSheet(QStringLiteral("color: #7f8c8d; margin-top: 10px;"));
            statsLabel->setText(QStringLiteral("Размер таблицы: —"));
            rightPanel->addWidget(statsLabel);

            rightPanel->addStretch();

            // Соединяем сигналы
            QObject::connect(generateButton, &QPushButton::clicked, parent,
                [sizeCombo, sloganEdit, fillerEdit, tableWidget, infoLabel, statsLabel]() {
                    int sizeType = sizeCombo->currentData().toInt();
                    QString slogan = sloganEdit->text().trimmed().toUpper();

                    // Получаем filler и нормализуем его
                    QString filler = fillerEdit->text().trimmed().toUpper();

                    // Если пусто или латиница X, заменяем на кириллицу Х
                    if (filler.isEmpty() || filler == "X" || filler == "x") {
                        filler = QStringLiteral("Х");
                        fillerEdit->setText(QStringLiteral("Х"));
                    } else if (filler.length() > 1) {
                        filler = filler.left(1);
                        fillerEdit->setText(filler);
                    }

                    if (slogan.isEmpty()) {
                        infoLabel->setText(QStringLiteral("⚠ Введите слово-лозунг"));
                        infoLabel->setStyleSheet(QStringLiteral("color: #e67e22; font-style: normal;"));
                        return;
                    }

                    // Создаем временный объект шифра для генерации таблицы
                    PlayfairCipher cipher;
                    auto table = cipher.generateTable(slogan,
                        static_cast<PlayfairCipher::MatrixSize>(sizeType));

                    int rows = table.size();
                    int cols = table[0].size();

                    tableWidget->setRowCount(rows);
                    tableWidget->setColumnCount(cols);

                    for (int i = 0; i < rows; i++) {
                        for (int j = 0; j < cols; j++) {
                            QTableWidgetItem* item = new QTableWidgetItem(QString(table[i][j]));
                            item->setTextAlignment(Qt::AlignCenter);
                            item->setFont(QFont(QStringLiteral("Courier"), 16, QFont::Bold));
                            item->setBackground(QBrush(QColor(236, 240, 241)));
                            item->setForeground(QBrush(QColor(44, 62, 80)));
                            tableWidget->setItem(i, j, item);
                        }
                    }

                    for (int j = 0; j < cols; j++) {
                        tableWidget->setColumnWidth(j, 50);
                    }
                    for (int i = 0; i < rows; i++) {
                        tableWidget->setRowHeight(i, 50);
                    }

                    QString sizeStr = (sizeType == 0) ? QStringLiteral("5×6 (30 букв)") : QStringLiteral("4×8 (32 буквы)");
                    statsLabel->setText(QString(QStringLiteral("Размер: %1 | Лозунг: %2 | Фиктивная буква: %3"))
                                        .arg(sizeStr).arg(slogan).arg(filler));

                    infoLabel->setText(QString(QStringLiteral("✓ Таблица %1x%2 успешно сгенерирована"))
                                        .arg(rows).arg(cols));
                    infoLabel->setStyleSheet(QStringLiteral("color: #27ae60; font-style: normal;"));
                });

            QObject::connect(example1Button, &QPushButton::clicked, parent,
                [sizeCombo, sloganEdit, fillerEdit, generateButton]() {
                    sizeCombo->setCurrentIndex(0);
                    sloganEdit->setText(QStringLiteral("РЕСПУБЛИКА"));
                    fillerEdit->setText(QStringLiteral("Х"));
                    generateButton->click();
                });

            QObject::connect(example2Button, &QPushButton::clicked, parent,
                [sizeCombo, sloganEdit, fillerEdit, generateButton]() {
                    sizeCombo->setCurrentIndex(1);
                    sloganEdit->setText(QStringLiteral("ЛОЗУНГ"));
                    fillerEdit->setText(QStringLiteral("Х"));
                    generateButton->click();
                });

            layout->addStretch();
        }
    );
}

// Статический регистратор
static PlayfairCipherRegister playfairCipherRegister;
