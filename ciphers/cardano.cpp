#include "cardano.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QStringBuilder>
#include <algorithm>
#include <QDebug>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QTableWidgetItem>
#include <QTimer>

CardanoCipher::CardanoCipher()
{
    m_holes = createDefaultGrid();
    m_rows = m_holes.size();
    if (m_rows > 0) {
        m_cols = m_holes[0].size();
    } else {
        m_cols = 0;
    }
    m_grid.resize(m_rows, std::vector<QChar>(m_cols, QChar()));
}

std::vector<std::vector<bool>> CardanoCipher::createDefaultGrid() const
{
    return {
        {0,1,0,0,0,0,0,0,0,0},  // 0100000000
        {1,0,0,0,1,0,1,1,0,0},  // 1000101100
        {0,1,0,0,0,1,0,0,0,1},  // 0100010001
        {0,0,0,1,0,0,0,1,0,0},  // 0001000100
        {0,1,0,0,0,0,0,0,0,0},  // 0100000000
        {0,0,1,0,0,1,1,0,0,1}   // 0010011001
    };
}

QChar CardanoCipher::getAlphabetChar(int index) const {
    static const QString alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    return alphabet[index % alphabet.size()];
}

// Поворот на 180 градусов
std::vector<std::vector<bool>> CardanoCipher::rotate180(const std::vector<std::vector<bool>>& pattern) const {
    int r = pattern.size();
    int c = pattern[0].size();
    std::vector<std::vector<bool>> rotated(r, std::vector<bool>(c, false));

    for (int i = 0; i < r; ++i) {
        for (int j = 0; j < c; ++j) {
            rotated[r-1-i][c-1-j] = pattern[i][j];
        }
    }

    return rotated;
}

std::vector<std::vector<bool>> CardanoCipher::mirrorX(const std::vector<std::vector<bool>>& pattern) const {
    int r = static_cast<int>(pattern.size());
    if (r == 0) return pattern;

    int c = static_cast<int>(pattern[0].size());
    std::vector<std::vector<bool>> mirrored(r, std::vector<bool>(c, false));

    for (int i = 0; i < r; ++i) {
        for (int j = 0; j < c; ++j) {
            mirrored[r-1-i][j] = pattern[i][j]; // Отражаем по горизонтальной оси
        }
    }

    return mirrored;
}

// Зеркальное отражение относительно вертикальной оси Y
std::vector<std::vector<bool>> CardanoCipher::mirrorY(const std::vector<std::vector<bool>>& pattern) const {
    int r = static_cast<int>(pattern.size());
    if (r == 0) return pattern;

    int c = static_cast<int>(pattern[0].size());
    std::vector<std::vector<bool>> mirrored(r, std::vector<bool>(c, false));

    for (int i = 0; i < r; ++i) {
        for (int j = 0; j < c; ++j) {
            mirrored[i][c-1-j] = pattern[i][j]; // Отражаем по вертикальной оси
        }
    }

    return mirrored;
}

// Получение позиции решетки для определенного шага
std::vector<std::vector<bool>> CardanoCipher::getPosition(int positionNumber) const {
    switch(positionNumber) {
        case 1: // Начальное положение
            return m_holes;

        case 2: // Поворот на 180 градусов
            return rotate180(m_holes);

        case 3: // Зеркально по оси X относительно первого
            return mirrorX(m_holes);

        case 4: // Зеркально по оси X относительно первого + поворот 180
        {
            std::vector<std::vector<bool>> mirrored = mirrorX(m_holes);
            return rotate180(mirrored);
        }

        default:
            return m_holes;
    }
}

// Публичный метод для получения отверстий
std::vector<std::vector<bool>> CardanoCipher::getHoles() const {
    return m_holes;
}

// Публичный метод для подсчета отверстий
int CardanoCipher::countTotalHoles() const {
    int total = 0;

    // Считаем отверстия для всех 4 позиций
    for (int pos = 1; pos <= 4; ++pos) {
        std::vector<std::vector<bool>> position = getPosition(pos);
        for (const auto& row : position) {
            for (bool hole : row) {
                if (hole) total++;
            }
        }
    }

    return total;
}

void CardanoCipher::clearGrid() {
    for (int i = 0; i < m_rows; ++i) {
        for (int j = 0; j < m_cols; ++j) {
            m_grid[i][j] = QChar();
        }
    }
}

CipherResult CardanoCipher::encrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    QVector<CipherStep> steps;

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    // Проверяем, что текст помещается
    int totalHoles = countTotalHoles();

    if (filteredText.length() > totalHoles) {
        filteredText = filteredText.left(totalHoles);
    }

    // Записываем текст через отверстия
    clearGrid();
    int textIndex = 0;

    // Все 4 позиции
    for (int pos = 1; pos <= 4; ++pos) {
        std::vector<std::vector<bool>> position = getPosition(pos);
        QString placedChars;

        for (int i = 0; i < m_rows; ++i) {
            for (int j = 0; j < m_cols; ++j) {
                if (position[i][j] && textIndex < filteredText.length()) {
                    m_grid[i][j] = filteredText[textIndex];
                    placedChars.append(filteredText[textIndex]);
                    textIndex++;
                }
            }
        }

        if (!placedChars.isEmpty()) {
            steps.append(CipherStep(
                pos,
                QChar(),
                placedChars,
                QString("Позиция %1: %2 букв").arg(pos).arg(placedChars.length())
            ));
        }
    }

    // Заполняем оставшиеся клетки
    QString result;
    int alphabetIndex = 0;

    for (int i = 0; i < m_rows; ++i) {
        for (int j = 0; j < m_cols; ++j) {
            if (m_grid[i][j].isNull()) {
                QChar ch = getAlphabetChar(alphabetIndex);
                m_grid[i][j] = ch;
                alphabetIndex++;
            }
            result += m_grid[i][j];
        }
    }

    steps.append(CipherStep(
        5,
        QChar(),
        result,
        QString("Итоговая матрица %1×%2").arg(m_rows).arg(m_cols)
    ));

    return CipherResult(result, steps, "Решетка Кардано 6×10", name(), false);
}

CipherResult CardanoCipher::decrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало дешифрования", "Инициализация"));

    // Фильтруем входной текст (оставляем только буквы алфавита)
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        steps.append(CipherStep(1, QChar(), "Ошибка: пустой входной текст", "Проверка"));
        return CipherResult(QString(), steps, "Решетка Кардано 6×10", name(), true);
    }

    // Проверяем, что длина текста соответствует размеру решетки
    int expectedLength = m_rows * m_cols;
    if (filteredText.length() != expectedLength) {
        // Если текст короче, дополняем его (хотя в реальности такого быть не должно)
        while (filteredText.length() < expectedLength) {
            filteredText.append(getAlphabetChar(0));
        }
        // Если длиннее, обрезаем
        if (filteredText.length() > expectedLength) {
            filteredText = filteredText.left(expectedLength);
        }

        steps.append(CipherStep(1, QChar(),
            QString("Текст скорректирован до длины %1 (ожидалось %2)").arg(filteredText.length()).arg(expectedLength),
            "Коррекция длины"));
    }

    // Заполняем рабочую решетку символами из входного текста
    int textIndex = 0;
    for (int i = 0; i < m_rows; ++i) {
        for (int j = 0; j < m_cols; ++j) {
            if (textIndex < filteredText.length()) {
                m_grid[i][j] = filteredText[textIndex++];
            }
        }
    }

    steps.append(CipherStep(2, QChar(),
        QString("Заполнена решетка %1×%2 символами").arg(m_rows).arg(m_cols),
        "Заполнение решетки"));

    // Собираем расшифрованный текст, проходя по всем 4 позициям в том же порядке, что и при шифровании
    QString result;
    int totalCharsFound = 0;

    for (int pos = 1; pos <= 4; ++pos) {
        std::vector<std::vector<bool>> position = getPosition(pos);
        QString collectedChars;

        for (int i = 0; i < m_rows; ++i) {
            for (int j = 0; j < m_cols; ++j) {
                // Если в текущей позиции есть отверстие и ячейка не пуста
                if (position[i][j] && !m_grid[i][j].isNull()) {
                    collectedChars.append(m_grid[i][j]);
                    result.append(m_grid[i][j]);
                    totalCharsFound++;
                }
            }
        }

        if (!collectedChars.isEmpty()) {
            steps.append(CipherStep(2 + pos, QChar(),
                QString("Позиция %1: найдено %2 букв: %3")
                    .arg(pos)
                    .arg(collectedChars.length())
                    .arg(collectedChars),
                QString("Сбор букв из позиции %1").arg(pos)));
        } else {
            steps.append(CipherStep(2 + pos, QChar(),
                QString("Позиция %1: букв не найдено").arg(pos),
                QString("Проверка позиции %1").arg(pos)));
        }
    }

    steps.append(CipherStep(7, QChar(),
        QString("Всего собрано %1 букв").arg(totalCharsFound),
        "Сбор завершен"));

    // Проверяем, что результат не пустой
    if (result.isEmpty()) {
        steps.append(CipherStep(8, QChar(),
            "Ошибка: не удалось извлечь ни одной буквы",
            "Проверка результата"));
        return CipherResult(QString(), steps, "Решетка Кардано 6×10", name(), true);
    }

    steps.append(CipherStep(9, QChar(),
        QString("Расшифрованный текст: %1").arg(result),
        "Формирование результата"));

    return CipherResult(result, steps, "Решетка Кардано 6×10", name(), false);
}

QString CardanoCipher::name() const {
    return QStringLiteral(u"Решетка Кардано");
}

QString CardanoCipher::description() const {
    return QStringLiteral("Перестановочный шифр с решеткой 6×10 (4 позиции)");
}

// Функция для отображения трафарета в таблице
void displayCardanoGrid(QTableWidget* tableWidget, const std::vector<std::vector<bool>>& grid, const QString& title) {
    Q_UNUSED(title);

    int rows = grid.size();
    int cols = grid[0].size();

    tableWidget->setRowCount(rows);
    tableWidget->setColumnCount(cols);

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            QTableWidgetItem* item = new QTableWidgetItem();

            if (grid[i][j]) {
                // Отверстие - черная плитка
                item->setBackground(QBrush(QColor(0, 0, 0))); // Черный
                item->setText(""); // Без текста
                item->setToolTip(QString("Отверстие [%1,%2]").arg(i+1).arg(j+1));
            } else {
                // Нет отверстия - белая плитка
                item->setBackground(QBrush(QColor(255, 255, 255))); // Белый
                item->setText(""); // Без текста
                item->setToolTip(QString("Закрыто [%1,%2]").arg(i+1).arg(j+1));
            }

            item->setTextAlignment(Qt::AlignCenter);
            item->setFlags(item->flags() & ~Qt::ItemIsEditable);
            tableWidget->setItem(i, j, item);
        }
    }

    // Устанавливаем размеры ячеек (стандартные, как в Playfair)
    for (int j = 0; j < cols; j++) {
        tableWidget->setColumnWidth(j, 40);
    }
    for (int i = 0; i < rows; i++) {
        tableWidget->setRowHeight(i, 40);
    }
}

CardanoCipherRegister::CardanoCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "cardano",
        "Кардано",
        []() -> CipherInterface* { return new CardanoCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "cardano",
        // Основные виджеты
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
        },
        // Расширенные виджеты
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(widgets);

            QHBoxLayout* mainLayout = new QHBoxLayout();
            layout->addLayout(mainLayout);

            QVBoxLayout* leftPanel = new QVBoxLayout();
            mainLayout->addLayout(leftPanel, 1);

            QVBoxLayout* rightPanel = new QVBoxLayout();
            mainLayout->addLayout(rightPanel, 2);
            // Кнопки для просмотра разных позиций - ВЕРТИКАЛЬНОЕ РАСПОЛОЖЕНИЕ
            QGroupBox* positionsGroup = new QGroupBox(QStringLiteral("Просмотр позиций"), parent);
            QVBoxLayout* positionsLayout = new QVBoxLayout(positionsGroup);
            positionsLayout->setSpacing(8); // Увеличиваем расстояние между кнопками

            QPushButton* pos1Button = new QPushButton(QStringLiteral("Позиция 1 (исходная)"), parent);
            pos1Button->setObjectName(QStringLiteral("pos1Button"));
            pos1Button->setStyleSheet("QPushButton { background-color: #3498db; color: white; padding: 6px; font-size: 11px; min-width: 150px; max-width: 180px; }");
            positionsLayout->addWidget(pos1Button);

            QPushButton* pos2Button = new QPushButton(QStringLiteral("Позиция 2 (поворот 180°)"), parent);
            pos2Button->setObjectName(QStringLiteral("pos2Button"));
            pos2Button->setStyleSheet("QPushButton { background-color: #3498db; color: white; padding: 6px; font-size: 11px; min-width: 150px; max-width: 180px; }");
            positionsLayout->addWidget(pos2Button);

            QPushButton* pos3Button = new QPushButton(QStringLiteral("Позиция 3 (зеркально X)"), parent);
            pos3Button->setObjectName(QStringLiteral("pos3Button"));
            pos3Button->setStyleSheet("QPushButton { background-color: #3498db; color: white; padding: 6px; font-size: 11px; min-width: 150px; max-width: 180px; }");
            positionsLayout->addWidget(pos3Button);

            QPushButton* pos4Button = new QPushButton(QStringLiteral("Позиция 4 (зеркально X + 180°)"), parent);
            pos4Button->setObjectName(QStringLiteral("pos4Button"));
            pos4Button->setStyleSheet("QPushButton { background-color: #3498db; color: white; padding: 6px; font-size: 11px; min-width: 150px; max-width: 180px; }");
            positionsLayout->addWidget(pos4Button);

            positionsLayout->addStretch(); // Добавляем растяжение внизу
            leftPanel->addWidget(positionsGroup);

            // Информация о количестве отверстий
            QGroupBox* statsGroup = new QGroupBox(QStringLiteral("Статистика"), parent);
            QVBoxLayout* statsLayout = new QVBoxLayout(statsGroup);

            QLabel* holesCountLabel = new QLabel(parent);
            holesCountLabel->setObjectName(QStringLiteral("holesCountLabel"));
            holesCountLabel->setText(QStringLiteral("Отверстий в позиции 1: 12"));
            holesCountLabel->setStyleSheet("color: #27ae60; font-weight: bold; font-size: 11px;");
            statsLayout->addWidget(holesCountLabel);

            QLabel* totalHolesLabel = new QLabel(parent);
            totalHolesLabel->setObjectName(QStringLiteral("totalHolesLabel"));

            // Создаем временный объект для подсчета
            CardanoCipher* tempCipher = new CardanoCipher();
            int totalHoles = tempCipher->countTotalHoles();
            totalHolesLabel->setText(QString("Всего отверстий (4 позиции): %1").arg(totalHoles));
            totalHolesLabel->setStyleSheet("color: #e67e22; font-weight: bold; font-size: 11px;");
            statsLayout->addWidget(totalHolesLabel);

            QLabel* capacityLabel = new QLabel(parent);
            capacityLabel->setObjectName(QStringLiteral("capacityLabel"));
            capacityLabel->setText(QString("Макс. длина текста: %1 символов").arg(totalHoles));
            capacityLabel->setStyleSheet("color: #7f8c8d; font-size: 11px;");
            statsLayout->addWidget(capacityLabel);

            leftPanel->addWidget(statsGroup);
            leftPanel->addStretch();

            // Правая панель - таблица с трафаретом
            QLabel* tableTitleLabel = new QLabel(QStringLiteral("Трафарет (черный = отверстие):"), parent);
            tableTitleLabel->setStyleSheet(QStringLiteral("font-weight: bold; font-size: 12px; margin-bottom: 5px;"));
            rightPanel->addWidget(tableTitleLabel);

            QFrame* tableFrame = new QFrame(parent);
            tableFrame->setFrameStyle(QFrame::Box);
            tableFrame->setLineWidth(2);
            tableFrame->setStyleSheet(QStringLiteral("QFrame { background-color: #2c3e50; border-radius: 5px; }"));

            QVBoxLayout* frameLayout = new QVBoxLayout(tableFrame);
            frameLayout->setContentsMargins(10, 10, 10, 10);

            QTableWidget* tableWidget = new QTableWidget(parent);
            tableWidget->setObjectName(QStringLiteral("gridDisplay"));
            tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
            tableWidget->horizontalHeader()->setVisible(false);
            tableWidget->verticalHeader()->setVisible(false);

            // УВЕЛИЧИВАЕМ РАЗМЕР ТАБЛИЦЫ
            tableWidget->setMinimumSize(450, 280); // Минимальный размер
            tableWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

            tableWidget->setStyleSheet(QStringLiteral(
                "QTableWidget { background-color: #ecf0f1; gridline-color: #34495e; }"
                "QTableWidget::item { padding: 0px; }"
            ));

            frameLayout->addWidget(tableWidget);
            rightPanel->addWidget(tableFrame);

            QLabel* posInfoLabel = new QLabel(parent);
            posInfoLabel->setObjectName(QStringLiteral("posInfoLabel"));
            posInfoLabel->setStyleSheet(QStringLiteral("color: #7f8c8d; margin-top: 5px; font-size: 11px;"));
            posInfoLabel->setText(QStringLiteral("Текущая позиция: 1 (исходная)"));
            rightPanel->addWidget(posInfoLabel);

            rightPanel->addStretch();

            // Создаем временный объект для работы
            CardanoCipher* tempCipher2 = new CardanoCipher();
            std::vector<std::vector<bool>> holes = tempCipher2->getHoles();

            // Отображаем исходную решетку
            displayCardanoGrid(tableWidget, holes, "Исходная решетка");

            // Подсчет отверстий в исходной позиции
            int holesInPos1 = 0;
            for (const auto& row : holes) {
                for (bool hole : row) {
                    if (hole) holesInPos1++;
                }
            }
            holesCountLabel->setText(QString("Отверстий в позиции 1: %1").arg(holesInPos1));

            // Соединяем сигналы для кнопок позиций
            QObject::connect(pos1Button, &QPushButton::clicked, parent,
                [tableWidget, posInfoLabel, holesCountLabel, tempCipher2]() {
                    std::vector<std::vector<bool>> holes = tempCipher2->getHoles();
                    displayCardanoGrid(tableWidget, holes, "Позиция 1");
                    posInfoLabel->setText(QStringLiteral("Текущая позиция: 1 (исходная)"));

                    // Подсчет отверстий
                    int holesCount = 0;
                    for (const auto& row : holes) {
                        for (bool hole : row) {
                            if (hole) holesCount++;
                        }
                    }
                    holesCountLabel->setText(QString("Отверстий в позиции 1: %1").arg(holesCount));
                });

            QObject::connect(pos2Button, &QPushButton::clicked, parent,
                [tableWidget, posInfoLabel, holesCountLabel, tempCipher2]() {
                    std::vector<std::vector<bool>> holes = tempCipher2->getHoles();
                    std::vector<std::vector<bool>> rotated = tempCipher2->rotate180(holes);
                    displayCardanoGrid(tableWidget, rotated, "Позиция 2");
                    posInfoLabel->setText(QStringLiteral("Текущая позиция: 2 (поворот 180°)"));

                    // Подсчет отверстий
                    int holesCount = 0;
                    for (const auto& row : rotated) {
                        for (bool hole : row) {
                            if (hole) holesCount++;
                        }
                    }
                    holesCountLabel->setText(QString("Отверстий в позиции 2: %1").arg(holesCount));
                });

            QObject::connect(pos3Button, &QPushButton::clicked, parent,
                [tableWidget, posInfoLabel, holesCountLabel, tempCipher2]() {
                    std::vector<std::vector<bool>> holes = tempCipher2->getHoles();
                    std::vector<std::vector<bool>> mirrored = tempCipher2->mirrorX(holes);
                    displayCardanoGrid(tableWidget, mirrored, "Позиция 3");
                    posInfoLabel->setText(QStringLiteral("Текущая позиция: 3 (зеркально по X)"));

                    // Подсчет отверстий
                    int holesCount = 0;
                    for (const auto& row : mirrored) {
                        for (bool hole : row) {
                            if (hole) holesCount++;
                        }
                    }
                    holesCountLabel->setText(QString("Отверстий в позиции 3: %1").arg(holesCount));
                });

            QObject::connect(pos4Button, &QPushButton::clicked, parent,
                [tableWidget, posInfoLabel, holesCountLabel, tempCipher2]() {
                    std::vector<std::vector<bool>> holes = tempCipher2->getHoles();
                    std::vector<std::vector<bool>> mirrored = tempCipher2->mirrorX(holes);
                    std::vector<std::vector<bool>> rotated = tempCipher2->rotate180(mirrored);
                    displayCardanoGrid(tableWidget, rotated, "Позиция 4");
                    posInfoLabel->setText(QStringLiteral("Текущая позиция: 4 (зеркально X + поворот 180°)"));

                    // Подсчет отверстий
                    int holesCount = 0;
                    for (const auto& row : rotated) {
                        for (bool hole : row) {
                            if (hole) holesCount++;
                        }
                    }
                    holesCountLabel->setText(QString("Отверстий в позиции 4: %1").arg(holesCount));
                });

            layout->addStretch();

            // Очистка временных объектов при закрытии
            QObject::connect(parent, &QObject::destroyed, [tempCipher, tempCipher2]() {
                delete tempCipher;
                delete tempCipher2;
            });
        }
    );
}

// Статический регистратор
static CardanoCipherRegister cardanoCipherRegister;
