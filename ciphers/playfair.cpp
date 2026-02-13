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
const QChar PlayfairCipher::DEFAULT_FILLER = QChar('Х');
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
        if (ch == QChar('Ё')) return QChar('Е');
        if (ch == QChar('Й')) return QChar('И');
        if (ch == QChar('Ъ')) return QChar('Ь');
    } else { // Size4x8
        if (ch == QChar('Ё')) return QChar('Е');
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

    int i = 0;
    while (i < text.length()) {
        if (i + 1 >= text.length()) {
            // Последний символ - добавляем фиктивную букву
            processed.append(text[i]);
            processed.append(filler);
            i++;
        } else if (text[i] == text[i + 1]) {
            // Две одинаковые буквы подряд
            processed.append(text[i]);
            processed.append(filler);
            i++; // Не увеличиваем i на 2, чтобы следующая итерация обработала вторую букву
        } else {
            // Нормальная биграмма
            processed.append(text[i]);
            processed.append(text[i + 1]);
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

    // Проверяем, что алфавит содержит нужное количество букв
    int expectedSize = rows * cols;
    if (alphabet.length() != expectedSize) {
        qWarning() << "Alphabet size mismatch!" << alphabet.length() << "!=" << expectedSize;
    }

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
    return Position();
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
            // При шифровании - вправо
            col1 = (pos1.col + 1) % cols;
            col2 = (pos2.col + 1) % cols;
        } else {
            // При дешифровании - влево
            col1 = (pos1.col - 1 + cols) % cols;
            col2 = (pos2.col - 1 + cols) % cols;
        }
        return QString(table[pos1.row][col1]) + QString(table[pos2.row][col2]);
    }
    else if (pos1.col == pos2.col) {
        // Один столбец
        int row1, row2;
        if (encrypt) {
            // При шифровании - вниз
            row1 = (pos1.row + 1) % rows;
            row2 = (pos2.row + 1) % rows;
        } else {
            // При дешифровании - вверх
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
    // Убираем все пробелы и разбиваем на биграммы
    cleaned.remove(' ');

    for (int i = 0; i < cleaned.length(); i += 2) {
        if (i + 1 < cleaned.length()) {
            result.append(cleaned.mid(i, 2));
        } else {
            // Если остался один символ (не должно быть при корректном шифровании)
            result.append(cleaned.mid(i, 1) + QStringLiteral("?"));
        }
    }

    return result;
}

bool PlayfairCipher::isFillerAndRemovable(const QString& text, int index, QChar filler) const
{
    if (text[index] != filler) return false;

    // Проверяем, является ли эта буква фиктивной (между одинаковыми или в конце)
    if (index == text.length() - 1) {
        // Последняя буква
        return true;
    }

    if (index > 0 && index < text.length() - 1 && text[index - 1] == text[index + 1]) {
        // Между одинаковыми буквами
        return true;
    }

    return false;
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
        QChar filler = params.contains("filler") ? params["filler"].toChar() : DEFAULT_FILLER;

        steps.append(CipherStep(1, QChar(),
            QString(QStringLiteral("Параметры: размер=%1, лозунг='%2', фиктивная буква='%3'"))
                .arg(size == Size5x6 ? QStringLiteral("5×6") : QStringLiteral("4×8")).arg(slogan).arg(filler),
            QStringLiteral("Загрузка параметров")));

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

            // Находим позиции букв
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
        QString description = QString(QStringLiteral("Шифр Плейфера\n"
                                    "════════════════════════════════════════\n"
                                    "Размер таблицы: %1x%2\n"
                                    "Слово-лозунг: %3\n"
                                    "Фиктивная буква: %4\n"
                                    "Исходный текст: %5 символов\n"
                                    "Биграмм: %6"))
                            .arg(size == Size5x6 ? QStringLiteral("5") : QStringLiteral("4"))
                            .arg(size == Size5x6 ? QStringLiteral("6") : QStringLiteral("8"))
                            .arg(slogan)
                            .arg(filler)
                            .arg(preparedText.length())
                            .arg(bigrams.size());

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
        QChar filler = params.contains("filler") ? params["filler"].toChar() : DEFAULT_FILLER;

        steps.append(CipherStep(1, QChar(),
            QString(QStringLiteral("Параметры: размер=%1, лозунг='%2', фиктивная буква='%3'"))
                .arg(size == Size5x6 ? QStringLiteral("5×6") : QStringLiteral("4×8")).arg(slogan).arg(filler),
            QStringLiteral("Загрузка параметров")));

        // Шаг 2: Создание таблицы (та же, что и при шифровании)
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

            // Находим позиции букв
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
        QString description = QString(QStringLiteral("Дешифрование шифра Плейфера\n"
                                    "════════════════════════════════════════\n"
                                    "Размер таблицы: %1x%2\n"
                                    "Слово-лозунг: %3\n"
                                    "Фиктивная буква: %4\n"
                                    "Биграмм в шифртексте: %5\n"
                                    "Получено символов: %6"))
                            .arg(size == Size5x6 ? QStringLiteral("5") : QStringLiteral("4"))
                            .arg(size == Size5x6 ? QStringLiteral("6") : QStringLiteral("8"))
                            .arg(slogan)
                            .arg(filler)
                            .arg(encryptedBigrams.size())
                            .arg(result.length());

        return CipherResult(result, steps, description, name() + QStringLiteral(" (дешифрование)"), false);

    } catch (const std::exception& e) {
        steps.append(CipherStep(99, QChar(),
            QString(QStringLiteral("Исключение: %1")).arg(e.what()),
            QStringLiteral("Ошибка выполнения")));
        return CipherResult("", steps, QStringLiteral("Шифр Плейфера (дешифрование, ошибка)"), name() + QStringLiteral(" (дешифрование)"), false);
    }
}

// Регистратор виджетов (исправленная версия)
PlayfairCipherRegister::PlayfairCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "playfair",
        "Шифр Плейфера",
        []() -> CipherInterface* { return new PlayfairCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "playfair",
        // Основные виджеты (на главном экране)
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QLabel* infoLabel = new QLabel(QStringLiteral("Ключ: слово-лозунг для заполнения таблицы 5×6 или 4×8"), parent);
            infoLabel->setStyleSheet(QStringLiteral("color: #7f8c8d; font-style: italic;"));
            infoLabel->setWordWrap(true);
            layout->addWidget(infoLabel);
        },
        // Расширенные виджеты (в отдельном окне)
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            // Создаем главный горизонтальный layout
            QHBoxLayout* mainLayout = new QHBoxLayout();
            layout->addLayout(mainLayout);

            // Левая панель - настройки
            QVBoxLayout* leftPanel = new QVBoxLayout();
            mainLayout->addLayout(leftPanel, 1); // 1 часть ширины

            // Правая панель - таблица
            QVBoxLayout* rightPanel = new QVBoxLayout();
            mainLayout->addLayout(rightPanel, 2); // 2 части ширины

            // ============= ЛЕВАЯ ПАНЕЛЬ =============
            // Группа выбора размерности
            QGroupBox* sizeGroup = new QGroupBox(QStringLiteral("Размерность таблицы"), parent);
            QVBoxLayout* sizeLayout = new QVBoxLayout(sizeGroup);

            QComboBox* sizeCombo = new QComboBox(parent);
            sizeCombo->setObjectName(QStringLiteral("matrixSize"));
            sizeCombo->addItem(QStringLiteral("5 × 6 (30 букв, исключаются Ё, Й, Ъ)"), 0);
            sizeCombo->addItem(QStringLiteral("4 × 8 (32 буквы, исключается только Ё)"), 1);
            sizeLayout->addWidget(sizeCombo);

            leftPanel->addWidget(sizeGroup);
            widgets[QStringLiteral("matrixSize")] = sizeCombo;

            // Группа ключа
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
            keyLayout->addWidget(fillerEdit);
            widgets[QStringLiteral("filler")] = fillerEdit;

            leftPanel->addWidget(keyGroup);

            // Кнопка генерации таблицы
            QPushButton* generateButton = new QPushButton(QStringLiteral("Сгенерировать таблицу"), parent);
            generateButton->setObjectName(QStringLiteral("generateTableButton"));
            generateButton->setStyleSheet(QStringLiteral("QPushButton { background-color: #3498db; color: white; padding: 8px; margin-top: 10px; }"));
            leftPanel->addWidget(generateButton);

            // Информационное поле
            QLabel* infoLabel = new QLabel(parent);
            infoLabel->setObjectName(QStringLiteral("infoLabel"));
            infoLabel->setWordWrap(true);
            infoLabel->setText(QStringLiteral("✓ Введите слово-лозунг и нажмите кнопку для генерации таблицы"));
            infoLabel->setStyleSheet(QStringLiteral("color: #7f8c8d; font-style: italic; margin-top: 10px;"));
            leftPanel->addWidget(infoLabel);

            // Кнопки примеров
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

            // ============= ПРАВАЯ ПАНЕЛЬ =============
            QLabel* tableTitleLabel = new QLabel(QStringLiteral("Сгенерированная таблица:"), parent);
            tableTitleLabel->setStyleSheet(QStringLiteral("font-weight: bold; font-size: 14px; margin-bottom: 10px;"));
            rightPanel->addWidget(tableTitleLabel);

            // Контейнер для таблицы с рамкой и фоном
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

            // Статистика таблицы
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
                    QString filler = fillerEdit->text().trimmed().toUpper();

                    if (slogan.isEmpty()) {
                        infoLabel->setText(QStringLiteral("⚠ Введите слово-лозунг"));
                        infoLabel->setStyleSheet(QStringLiteral("color: #e67e22; font-style: normal;"));
                        return;
                    }

                    if (filler.isEmpty()) {
                        filler = QStringLiteral("Х");
                        fillerEdit->setText(QStringLiteral("Х"));
                    }

                    // Создаем временный объект шифра для генерации таблицы
                    PlayfairCipher cipher;
                    auto table = cipher.generateTable(slogan,
                        static_cast<PlayfairCipher::MatrixSize>(sizeType));

                    // Отображаем таблицу
                    int rows = table.size();
                    int cols = table[0].size();

                    tableWidget->setRowCount(rows);
                    tableWidget->setColumnCount(cols);

                    // Устанавливаем размер ячеек
                    for (int i = 0; i < rows; i++) {
                        for (int j = 0; j < cols; j++) {
                            QTableWidgetItem* item = new QTableWidgetItem(QString(table[i][j]));
                            item->setTextAlignment(Qt::AlignCenter);
                            item->setFont(QFont(QStringLiteral("Courier"), 16, QFont::Bold));
                            item->setBackground(QBrush(QColor(236, 240, 241))); // Светло-серый фон
                            item->setForeground(QBrush(QColor(44, 62, 80))); // Темно-синий текст
                            tableWidget->setItem(i, j, item);
                        }
                    }

                    tableWidget->resizeColumnsToContents();
                    tableWidget->resizeRowsToContents();

                    // Устанавливаем минимальную ширину колонок
                    for (int j = 0; j < cols; j++) {
                        tableWidget->setColumnWidth(j, 50);
                    }
                    for (int i = 0; i < rows; i++) {
                        tableWidget->setRowHeight(i, 50);
                    }

                    // Обновляем статистику
                    QString sizeStr = (sizeType == 0) ? QStringLiteral("5×6 (30 букв)") : QStringLiteral("4×8 (32 буквы)");
                    statsLabel->setText(QString(QStringLiteral("Размер: %1 | Лозунг: %2 | Фиктивная буква: %3"))
                                        .arg(sizeStr).arg(slogan).arg(filler));

                    infoLabel->setText(QString(QStringLiteral("✓ Таблица %1x%2 успешно сгенерирована"))
                                        .arg(rows).arg(cols));
                    infoLabel->setStyleSheet(QStringLiteral("color: #27ae60; font-style: normal;"));
                });

            QObject::connect(example1Button, &QPushButton::clicked, parent,
                [sizeCombo, sloganEdit, fillerEdit, generateButton]() {
                    sizeCombo->setCurrentIndex(0); // 5x6
                    sloganEdit->setText(QStringLiteral("РЕСПУБЛИКА"));
                    fillerEdit->setText(QStringLiteral("Х"));
                    generateButton->click();
                });

            QObject::connect(example2Button, &QPushButton::clicked, parent,
                [sizeCombo, sloganEdit, fillerEdit, generateButton]() {
                    sizeCombo->setCurrentIndex(1); // 4x8
                    sloganEdit->setText(QStringLiteral("ЛОЗУНГ"));
                    fillerEdit->setText(QStringLiteral("Х"));
                    generateButton->click();
                });

            // Добавляем stretch в основной layout
            layout->addStretch();
        }
    );
}

// Статический регистратор
static PlayfairCipherRegister playfairCipherRegister;
