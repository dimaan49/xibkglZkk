#include "routecipherwidget.h"
#include <random>
#include <QMessageBox>
#include <QHeaderView>
#include <QDebug>
#include <QScrollArea>

RouteCipherAdvancedWidget::RouteCipherAdvancedWidget(QWidget *parent)
    : QWidget(parent)
    , m_currentRows(4)
    , m_currentCols(4)
    , m_updating(false)
    , m_tabWidget(nullptr)
    , m_directionsTab(nullptr)
    , m_writeGroup(nullptr)
    , m_zigzagBtn(nullptr)
    , m_allWriteLeftBtn(nullptr)
    , m_allWriteRightBtn(nullptr)
    , m_writeGrid(nullptr)
    , m_readGroup(nullptr)
    , m_allReadTopBtn(nullptr)
    , m_allReadBottomBtn(nullptr)
    , m_readGrid(nullptr)
    , m_orderTab(nullptr)
    , m_rowOrderGroup(nullptr)
    , m_rowOrderList(nullptr)
    , m_rowOrderNormalizeBtn(nullptr)
    , m_rowOrderReverseBtn(nullptr)
    , m_colOrderGroup(nullptr)
    , m_colOrderList(nullptr)
    , m_colOrderNormalizeBtn(nullptr)
    , m_colOrderReverseBtn(nullptr)
    , m_rowOrderSpinsWidget(nullptr)
    , m_colOrderSpinsWidget(nullptr)
    , m_previewTab(nullptr)
    , m_previewTable(nullptr)
    , m_writePathLabel(nullptr)
    , m_readPathLabel(nullptr)
    , m_tableInfoLabel(nullptr)
    , m_fillExampleBtn(nullptr)
    , m_randomizeAllBtn(nullptr)
    , m_resetBtn(nullptr)
{
    setupUI();
    resetToDefault();
}

RouteCipherAdvancedWidget::~RouteCipherAdvancedWidget()
{
}

void RouteCipherAdvancedWidget::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    // Верхняя панель с размерами
    QWidget* sizeWidget = new QWidget(this);
    QHBoxLayout* sizeLayout = new QHBoxLayout(sizeWidget);
    sizeLayout->setSpacing(15);
    sizeLayout->setContentsMargins(0, 0, 0, 0);

    m_autoSizeCheck = new QCheckBox("Автоопределение размера", sizeWidget);
    m_autoSizeCheck->setChecked(true);
    m_autoSizeCheck->setToolTip("Автоматически подобрать размер таблицы под длину текста");

    QLabel* rowsLabel = new QLabel("Строки:", sizeWidget);
    m_rowsSpin = new QSpinBox(sizeWidget);
    m_rowsSpin->setRange(2,  MAX_VISIBLE_ROWS);
    m_rowsSpin->setValue(4);
    m_rowsSpin->setEnabled(false);
    m_rowsSpin->setToolTip("Количество строк (при отключенном автоопределении)");

    QLabel* colsLabel = new QLabel("Столбцы:", sizeWidget);
    m_colsSpin = new QSpinBox(sizeWidget);
    m_colsSpin->setRange(2, MAX_VISIBLE_COLS);
    m_colsSpin->setValue(4);
    m_colsSpin->setEnabled(false);
    m_colsSpin->setToolTip("Количество столбцов (при отключенном автоопределении)");

    m_sizeInfoLabel = new QLabel("Размер будет определен автоматически", sizeWidget);
    m_sizeInfoLabel->setStyleSheet("color: gray; font-style: italic;");

    sizeLayout->addWidget(m_autoSizeCheck);
    sizeLayout->addWidget(rowsLabel);
    sizeLayout->addWidget(m_rowsSpin);
    sizeLayout->addWidget(colsLabel);
    sizeLayout->addWidget(m_colsSpin);
    sizeLayout->addStretch();
    sizeLayout->addWidget(m_sizeInfoLabel);

    mainLayout->addWidget(sizeWidget);

    // Подключение сигналов для размеров
    connect(m_autoSizeCheck, &QCheckBox::toggled, this, &RouteCipherAdvancedWidget::onAutoSizeToggled);
    connect(m_rowsSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &RouteCipherAdvancedWidget::onRowsChanged);
    connect(m_colsSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &RouteCipherAdvancedWidget::onColsChanged);

    // Таб-виджет
    m_tabWidget = new QTabWidget(this);

    // Вкладка направлений
    m_directionsTab = new QWidget();
    createDirectionControls();
    m_tabWidget->addTab(m_directionsTab, "↔ Направления");

    // Вкладка порядка
    m_orderTab = new QWidget();
    createOrderControls();
    m_tabWidget->addTab(m_orderTab, "# Порядок");

    // Вкладка предпросмотра
    m_previewTab = new QWidget();
    createTablePreview();
    m_tabWidget->addTab(m_previewTab, "👁 Предпросмотр");

    mainLayout->addWidget(m_tabWidget);

    // Нижняя панель с кнопками
    QHBoxLayout* bottomLayout = new QHBoxLayout();

    m_fillExampleBtn = new QPushButton("📝 Заполнить пример", this);
    m_fillExampleBtn->setToolTip("Заполнить таблицу примером текста");

    m_randomizeAllBtn = new QPushButton("🎲 Случайные параметры", this);
    m_randomizeAllBtn->setToolTip("Сгенерировать случайные направления и порядок");

    bottomLayout->addWidget(m_fillExampleBtn);
    bottomLayout->addWidget(m_randomizeAllBtn);
    bottomLayout->addStretch();

    m_resetBtn = new QPushButton("↺ Сброс", this);
    m_resetBtn->setToolTip("Сбросить к настройкам по умолчанию");
    bottomLayout->addWidget(m_resetBtn);

    mainLayout->addLayout(bottomLayout);

    // Подключение сигналов
    connect(m_fillExampleBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onFillExample);
    connect(m_randomizeAllBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onRandomizeAll);
    connect(m_resetBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onResetToDefault);
    connect(m_tabWidget, &QTabWidget::currentChanged, this, &RouteCipherAdvancedWidget::onTabChanged);
}

void RouteCipherAdvancedWidget::createDirectionControls()
{
    // Горизонтальный layout для двух колонок
    QHBoxLayout* mainLayout = new QHBoxLayout(m_directionsTab);
    mainLayout->setSpacing(20);

    // === ЛЕВАЯ КОЛОНКА: Направления записи (строки) ===
    m_writeGroup = new QGroupBox("Направления записи (по строкам)", m_directionsTab);
    QVBoxLayout* writeLayout = new QVBoxLayout(m_writeGroup);

    QLabel* writeHint = new QLabel("← → Как заполняются строки", m_writeGroup);
    writeHint->setStyleSheet("color: gray; font-style: italic;");
    writeLayout->addWidget(writeHint);

    // Создаем виджет с прокруткой для комбобоксов
    QWidget* writeScrollContent = new QWidget();
    m_writeGrid = new QGridLayout(writeScrollContent);
    m_writeGrid->setVerticalSpacing(5);

    // Используем MAX_VISIBLE_ROWS из .h файла
    for (int i = 0; i < MAX_VISIBLE_ROWS; ++i) {
        QLabel* label = new QLabel(QString("Строка %1:").arg(i + 1), m_writeGroup);
        QComboBox* combo = new QComboBox(m_writeGroup);
        combo->addItem("→", LEFT_TO_RIGHT);
        combo->addItem("←", RIGHT_TO_LEFT);
        combo->setCurrentIndex(i % 2);
        combo->setProperty("rowIndex", i);

        connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &RouteCipherAdvancedWidget::onWriteDirectionChanged);

        m_writeDirectionCombos.append(combo);
        m_writeGrid->addWidget(label, i, 0);
        m_writeGrid->addWidget(combo, i, 1);
    }

    QScrollArea* writeScrollArea = new QScrollArea();
    writeScrollArea->setWidget(writeScrollContent);
    writeScrollArea->setWidgetResizable(true);
    writeScrollArea->setMaximumHeight(300);
    writeLayout->addWidget(writeScrollArea);

    // Кнопки быстрых действий для строк
    QHBoxLayout* writeButtonsLayout = new QHBoxLayout();
    m_zigzagBtn = new QPushButton("Змейка", m_writeGroup);
    m_allWriteLeftBtn = new QPushButton("Все →", m_writeGroup);
    m_allWriteRightBtn = new QPushButton("Все ←", m_writeGroup);

    writeButtonsLayout->addWidget(m_zigzagBtn);
    writeButtonsLayout->addWidget(m_allWriteLeftBtn);
    writeButtonsLayout->addWidget(m_allWriteRightBtn);
    writeButtonsLayout->addStretch();
    writeLayout->addLayout(writeButtonsLayout);

    // === ПРАВАЯ КОЛОНКА: Направления чтения (столбцы) ===
    m_readGroup = new QGroupBox("Направления чтения (по столбцам)", m_directionsTab);
    QVBoxLayout* readLayout = new QVBoxLayout(m_readGroup);

    QLabel* readHint = new QLabel("↑ ↓ Как читаются столбцы", m_readGroup);
    readHint->setStyleSheet("color: gray; font-style: italic;");
    readLayout->addWidget(readHint);

    QWidget* readScrollContent = new QWidget();
    m_readGrid = new QGridLayout(readScrollContent);
    m_readGrid->setVerticalSpacing(5);

    // Используем MAX_VISIBLE_COLS из .h файла
    for (int i = 0; i < MAX_VISIBLE_COLS; ++i) {
        QLabel* label = new QLabel(QString("Столбец %1:").arg(i + 1), m_readGroup);
        QComboBox* combo = new QComboBox(m_readGroup);
        combo->addItem("↓", TOP_TO_BOTTOM);
        combo->addItem("↑", BOTTOM_TO_TOP);
        combo->setCurrentIndex(0);
        combo->setProperty("colIndex", i);

        connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &RouteCipherAdvancedWidget::onReadDirectionChanged);

        m_readDirectionCombos.append(combo);
        m_readGrid->addWidget(label, i, 0);
        m_readGrid->addWidget(combo, i, 1);
    }

    QScrollArea* readScrollArea = new QScrollArea();
    readScrollArea->setWidget(readScrollContent);
    readScrollArea->setWidgetResizable(true);
    readScrollArea->setMaximumHeight(300);
    readLayout->addWidget(readScrollArea);

    // Кнопки быстрых действий для столбцов
    QHBoxLayout* readButtonsLayout = new QHBoxLayout();
    m_allReadTopBtn = new QPushButton("Все ↓", m_readGroup);
    m_allReadBottomBtn = new QPushButton("Все ↑", m_readGroup);

    readButtonsLayout->addWidget(m_allReadTopBtn);
    readButtonsLayout->addWidget(m_allReadBottomBtn);
    readButtonsLayout->addStretch();
    readLayout->addLayout(readButtonsLayout);

    // Добавляем обе группы в горизонтальный layout
    mainLayout->addWidget(m_writeGroup, 1);
    mainLayout->addWidget(m_readGroup, 1);

    // Подключение сигналов для кнопок
    connect(m_zigzagBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onZigzagClicked);
    connect(m_allWriteLeftBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onAllWriteLeftClicked);
    connect(m_allWriteRightBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onAllWriteRightClicked);
    connect(m_allReadTopBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onAllReadTopClicked);
    connect(m_allReadBottomBtn, &QPushButton::clicked, this, &RouteCipherAdvancedWidget::onAllReadBottomClicked);
}

void RouteCipherAdvancedWidget::createOrderControls()
{
    QHBoxLayout* mainLayout = new QHBoxLayout(m_orderTab);
    mainLayout->setSpacing(20);

    // === Левая колонка: порядок строк ===
    QVBoxLayout* leftColumn = new QVBoxLayout();

    m_rowOrderGroup = new QGroupBox("Порядок строк", m_orderTab);
    QVBoxLayout* rowGroupLayout = new QVBoxLayout(m_rowOrderGroup);

    QLabel* rowHint = new QLabel("Перетаскивайте строки для изменения порядка заполнения", m_rowOrderGroup);
    rowHint->setStyleSheet("color: gray; font-style: italic;");
    rowHint->setWordWrap(true);
    rowGroupLayout->addWidget(rowHint);

    m_rowOrderList = new QListWidget(m_rowOrderGroup);
    m_rowOrderList->setDragDropMode(QListWidget::InternalMove);
    m_rowOrderList->setSelectionMode(QListWidget::SingleSelection);
    m_rowOrderList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Используем MAX_VISIBLE_ROWS
    for (int i = 0; i < MAX_VISIBLE_ROWS; ++i) {
        QListWidgetItem* item = new QListWidgetItem(QString("Строка %1").arg(i + 1));
        item->setData(Qt::UserRole, i);
        m_rowOrderList->addItem(item);
    }

    rowGroupLayout->addWidget(m_rowOrderList);

    QHBoxLayout* rowButtonsLayout = new QHBoxLayout();
    m_rowOrderNormalizeBtn = new QPushButton("1,2,3...", m_rowOrderGroup);
    m_rowOrderNormalizeBtn->setToolTip("Восстановить нормальный порядок (1,2,3...)");

    m_rowOrderReverseBtn = new QPushButton("Обратный", m_rowOrderGroup);
    m_rowOrderReverseBtn->setToolTip("Обратный порядок");

    rowButtonsLayout->addWidget(m_rowOrderNormalizeBtn);
    rowButtonsLayout->addWidget(m_rowOrderReverseBtn);
    rowButtonsLayout->addStretch();

    rowGroupLayout->addLayout(rowButtonsLayout);
    leftColumn->addWidget(m_rowOrderGroup);

    // === Правая колонка: порядок столбцов ===
    QVBoxLayout* rightColumn = new QVBoxLayout();

    m_colOrderGroup = new QGroupBox("Порядок столбцов", m_orderTab);
    QVBoxLayout* colGroupLayout = new QVBoxLayout(m_colOrderGroup);

    QLabel* colHint = new QLabel("Перетаскивайте столбцы для изменения порядка чтения", m_colOrderGroup);
    colHint->setStyleSheet("color: gray; font-style: italic;");
    colHint->setWordWrap(true);
    colGroupLayout->addWidget(colHint);

    m_colOrderList = new QListWidget(m_colOrderGroup);
    m_colOrderList->setDragDropMode(QListWidget::InternalMove);
    m_colOrderList->setSelectionMode(QListWidget::SingleSelection);
    m_colOrderList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Используем MAX_VISIBLE_COLS
    for (int i = 0; i < MAX_VISIBLE_COLS; ++i) {
        QListWidgetItem* item = new QListWidgetItem(QString("Столбец %1").arg(i + 1));
        item->setData(Qt::UserRole, i);
        m_colOrderList->addItem(item);
    }

    colGroupLayout->addWidget(m_colOrderList);

    QHBoxLayout* colButtonsLayout = new QHBoxLayout();
    m_colOrderNormalizeBtn = new QPushButton("1,2,3...", m_colOrderGroup);
    m_colOrderReverseBtn = new QPushButton("Обратный", m_colOrderGroup);

    colButtonsLayout->addWidget(m_colOrderNormalizeBtn);
    colButtonsLayout->addWidget(m_colOrderReverseBtn);
    colButtonsLayout->addStretch();

    colGroupLayout->addLayout(colButtonsLayout);

    rightColumn->addWidget(m_colOrderGroup);

    mainLayout->addLayout(leftColumn, 1);
    mainLayout->addLayout(rightColumn, 1);

    // Подключение сигналов для списков
    connect(m_rowOrderList->model(), &QAbstractItemModel::rowsMoved,
            this, &RouteCipherAdvancedWidget::onRowListChanged);
    connect(m_colOrderList->model(), &QAbstractItemModel::rowsMoved,
            this, &RouteCipherAdvancedWidget::onColumnListChanged);

    // Подключение сигналов для кнопок
    connect(m_rowOrderNormalizeBtn, &QPushButton::clicked,
            this, &RouteCipherAdvancedWidget::onRowOrderNormalize);
    connect(m_rowOrderReverseBtn, &QPushButton::clicked,
            this, &RouteCipherAdvancedWidget::onRowOrderReverse);
    connect(m_colOrderNormalizeBtn, &QPushButton::clicked,
            this, &RouteCipherAdvancedWidget::onColumnOrderNormalize);
    connect(m_colOrderReverseBtn, &QPushButton::clicked,
            this, &RouteCipherAdvancedWidget::onColumnOrderReverse);
}

void RouteCipherAdvancedWidget::createTablePreview()
{
    // Очищаем вкладку предпросмотра
    if (m_previewTab->layout()) {
        delete m_previewTab->layout();
    }

    QVBoxLayout* mainLayout = new QVBoxLayout(m_previewTab);
    mainLayout->setContentsMargins(5, 5, 5, 5);
    mainLayout->setSpacing(5);

    // Контейнер для таблицы с прокруткой
    QScrollArea* scrollArea = new QScrollArea(m_previewTab);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* container = new QWidget();
    QVBoxLayout* containerLayout = new QVBoxLayout(container);
    containerLayout->setContentsMargins(0, 0, 0, 0);
    containerLayout->setSpacing(5);

    // Заголовок
    QLabel* tableTitle = new QLabel("📊 Предпросмотр таблицы", container);
    tableTitle->setStyleSheet(
        "QLabel {"
        "   color: #b4bece;"
        "   font-weight: bold;"
        "   font-size: 12px;"
        "   padding: 4px;"
        "   background-color: #2a3a4d;"
        "   border-radius: 4px;"
        "}"
    );
    tableTitle->setAlignment(Qt::AlignCenter);
    containerLayout->addWidget(tableTitle);

    // Таблица для предпросмотра
    if (m_previewTable) {
        delete m_previewTable;
    }
    m_previewTable = new QTableWidget(container);
    m_previewTable->setObjectName("previewTable");
    m_previewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_previewTable->setSelectionMode(QAbstractItemView::NoSelection);

    // Настройка внешнего вида
    m_previewTable->horizontalHeader()->setVisible(true);
    m_previewTable->verticalHeader()->setVisible(true);

    m_previewTable->horizontalHeader()->setStyleSheet(
        "QHeaderView::section {"
        "   background-color: #2a3a4d;"
        "   color: #b4bece;"
        "   border: 1px solid #334155;"
        "   padding: 4px;"
        "   font-weight: bold;"
        "}"
    );

    m_previewTable->verticalHeader()->setStyleSheet(
        "QHeaderView::section {"
        "   background-color: #2a3a4d;"
        "   color: #b4bece;"
        "   border: 1px solid #334155;"
        "   padding: 4px;"
        "   font-weight: bold;"
        "}"
    );

    m_previewTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_previewTable->setMinimumSize(400, 300);

    containerLayout->addWidget(m_previewTable);

    // Информационная строка
    QFrame* infoFrame = new QFrame(container);
    infoFrame->setStyleSheet(
        "QFrame {"
        "   background-color: #1a1a1a;"
        "   border: 1px solid #2a2a2a;"
        "   border-radius: 4px;"
        "   padding: 4px;"
        "}"
    );

    QHBoxLayout* infoLayout = new QHBoxLayout(infoFrame);
    infoLayout->setContentsMargins(5, 2, 5, 2);

    if (!m_tableInfoLabel) {
        m_tableInfoLabel = new QLabel("4 × 4", infoFrame);
        m_tableInfoLabel->setStyleSheet("QLabel { color: #b4bece; font-weight: bold; font-size: 12px; }");
    } else {
        m_tableInfoLabel->setParent(infoFrame);
    }
    m_tableInfoLabel->setAlignment(Qt::AlignCenter);

    infoLayout->addStretch();
    infoLayout->addWidget(m_tableInfoLabel);
    infoLayout->addStretch();

    containerLayout->addWidget(infoFrame);

    scrollArea->setWidget(container);
    mainLayout->addWidget(scrollArea);

    updateTablePreview();
}

void RouteCipherAdvancedWidget::updateTablePreview()
{
    if (!m_previewTable) return;

    // Показываем все строки и столбцы
    int rows = qMin(m_currentRows, PREVIEW_MAX_SIZE);
    int cols = qMin(m_currentCols, PREVIEW_MAX_SIZE);

    m_previewTable->setRowCount(rows);
    m_previewTable->setColumnCount(cols);

    // Размер ячеек (как было)
    int cellSize = 35;
    if (rows > 12 || cols > 12) cellSize = 30;
    if (rows > 16 || cols > 16) cellSize = 25;

    for (int i = 0; i < rows; ++i) {
        m_previewTable->setRowHeight(i, cellSize);
    }
    for (int j = 0; j < cols; ++j) {
        m_previewTable->setColumnWidth(j, cellSize);
    }

    // Получаем направления и порядок
    QVector<Direction> writeDirs = getWriteDirections();
    QVector<int> rowOrder = getRowOrder();      // например, [2,1,3] значит: сначала строка 2, потом 1, потом 3
    QVector<int> colOrder = getColumnOrder();   // например, [3,1,2] значит: сначала столбец 3, потом 1, потом 2

    // Подготавливаем текст для заполнения
    QString text = m_previewText;
    if (text.isEmpty()) {
        text = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";  // Заглушка если нет текста
    }

    // Создаем временную таблицу для заполнения
    std::vector<std::vector<QChar>> tempTable(rows, std::vector<QChar>(cols, QChar()));
    int textIndex = 0;

    // Заполняем таблицу в порядке строк (rowOrder)
    for (int orderPos = 0; orderPos < rows && textIndex < text.length(); ++orderPos) {
        // Какая строка идет в этом порядке
        int rowIdx = rowOrder[orderPos] - 1;  // rowOrder хранит номера строк (1..N)

        if (rowIdx >= rows) continue;

        // Направление для этой строки
        Direction dir = LEFT_TO_RIGHT;
        if (rowIdx < writeDirs.size()) {
            dir = writeDirs[rowIdx];
        }

        // Заполняем строку
        if (dir == LEFT_TO_RIGHT) {
            for (int j = 0; j < cols && textIndex < text.length(); ++j) {
                tempTable[rowIdx][j] = text[textIndex++];
            }
        } else { // RIGHT_TO_LEFT
            for (int j = cols - 1; j >= 0 && textIndex < text.length(); --j) {
                tempTable[rowIdx][j] = text[textIndex++];
            }
        }
    }

    // Заполняем таблицу предпросмотра
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            QTableWidgetItem* item = m_previewTable->item(i, j);
            if (!item) {
                item = new QTableWidgetItem();
                m_previewTable->setItem(i, j, item);
            }

            // Устанавливаем текст
            QChar ch = tempTable[i][j];
            if (ch.isNull()) {
                item->setText("·");  // Пустая ячейка
                item->setForeground(QBrush(QColor("#888888")));
            } else {
                item->setText(ch);
                item->setForeground(QBrush(QColor("#f0f5ff")));
            }

            item->setTextAlignment(Qt::AlignCenter);

            // Подсветка строк (как было)
            if (i < m_writeDirectionCombos.size()) {
                Direction dir = static_cast<Direction>(m_writeDirectionCombos[i]->currentData().toInt());
                if (dir == LEFT_TO_RIGHT) {
                    item->setBackground(QColor(0, 150, 255, 40));  // Синяя для →
                } else {
                    item->setBackground(QColor(255, 100, 0, 40));  // Оранжевая для ←
                }
            }
        }
    }

    // Заголовки строк (как было)
    QStringList rowHeaders;
    for (int i = 0; i < rows; ++i) {
        rowHeaders << QString::number(i + 1);
    }
    m_previewTable->setVerticalHeaderLabels(rowHeaders);

    // Заголовки столбцов с отображением порядка чтения
    QStringList colHeaders;
    for (int j = 0; j < cols; ++j) {
        // Создаем карту: номер столбца -> его позиция в порядке чтения
        int readOrder = 0;
        for (int pos = 0; pos < colOrder.size(); ++pos) {
            if (colOrder[pos] == j + 1) {
                readOrder = pos + 1;
                break;
            }
        }

        if (readOrder > 0) {
            colHeaders << QString("%1 (%2)").arg(j + 1).arg(readOrder);
        } else {
            colHeaders << QString::number(j + 1);
        }
    }
    m_previewTable->setHorizontalHeaderLabels(colHeaders);

    // Обновляем метку размера
    if (m_tableInfoLabel) {
        m_tableInfoLabel->setText(QString("%1 × %2").arg(m_currentRows).arg(m_currentCols));
    }
}

QString RouteCipherAdvancedWidget::directionToString(Direction dir, bool isWrite) const
{
    if (isWrite) {
        return (dir == LEFT_TO_RIGHT) ? "слева направо" : "справа налево";
    } else {
        return (dir == TOP_TO_BOTTOM) ? "сверху вниз" : "снизу вверх";
    }
}

// ==================== СЛОТЫ ====================


void RouteCipherAdvancedWidget::onAutoSizeToggled(bool checked)
{
    m_rowsSpin->setEnabled(!checked);
    m_colsSpin->setEnabled(!checked);

    if (checked) {
        m_sizeInfoLabel->setText("Размер будет определен автоматически");
        m_currentRows = 4;
        m_currentCols = 4;
    } else {
        m_sizeInfoLabel->setText(QString("Фиксированный размер: %1×%2")
                                 .arg(m_rowsSpin->value())
                                 .arg(m_colsSpin->value()));
        m_currentRows = m_rowsSpin->value();
        m_currentCols = m_colsSpin->value();
    }

    onRowsChanged(m_currentRows);
    onColsChanged(m_currentCols);

    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onFillExample()
{
    // Создаем пример текста (буквы алфавита)
    QString exampleText = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

    // Получаем текущие направления и порядок
    QVector<Direction> writeDirs = getWriteDirections();
    QVector<int> rowOrd = getRowOrder();

    // Создаем временную таблицу для примера
    int rows = m_currentRows;
    int cols = m_currentCols;

    // Очищаем таблицу предпросмотра
    for (int i = 0; i < rows && i < 6; ++i) {
        for (int j = 0; j < cols && j < 6; ++j) {
            if (i < m_previewTable->rowCount() && j < m_previewTable->columnCount()) {
                QTableWidgetItem* item = m_previewTable->item(i, j);
                if (item) {
                    // Заполняем буквами по порядку
                    int index = (i * cols + j) % exampleText.length();
                    item->setText(exampleText.mid(index, 1));

                    // Подсветка в зависимости от направления
                    if (i < m_writeDirectionCombos.size()) {
                        Direction dir = static_cast<Direction>(m_writeDirectionCombos[i]->currentData().toInt());
                        if (dir == LEFT_TO_RIGHT) {
                            item->setBackground(QColor(200, 230, 255));
                        } else {
                            item->setBackground(QColor(255, 220, 200));
                        }
                    }
                }
            }
        }
    }

    // Обновляем заголовки
    updateTablePreview();
}

void RouteCipherAdvancedWidget::onRandomizeAll()
{
    m_updating = true;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dirDis(0, 1);

    for (auto combo : m_writeDirectionCombos) {
        combo->setCurrentIndex(dirDis(gen));
    }

    for (auto combo : m_readDirectionCombos) {
        combo->setCurrentIndex(dirDis(gen));
    }

    QVector<int> rowIndices;
    for (int i = 0; i < m_currentRows; ++i) rowIndices.append(i);
    std::shuffle(rowIndices.begin(), rowIndices.end(), gen);

    for (int pos = 0; pos < rowIndices.size() && pos < m_rowOrderList->count(); ++pos) {
        QListWidgetItem* item = m_rowOrderList->item(pos);
        if (item) {
            item->setData(Qt::UserRole, rowIndices[pos]);
            item->setText(QString("Строка %1").arg(rowIndices[pos] + 1));
        }
    }

    m_updating = false;

    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onResetToDefault()
{
    m_updating = true;

    m_autoSizeCheck->setChecked(true);
    m_rowsSpin->setValue(4);
    m_colsSpin->setValue(4);

    for (int i = 0; i < m_writeDirectionCombos.size(); ++i) {
        m_writeDirectionCombos[i]->setCurrentIndex(i % 2);
    }

    for (auto combo : m_readDirectionCombos) {
        combo->setCurrentIndex(0);
    }

    for (int i = 0; i < m_rowOrderList->count(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, i);
            item->setText(QString("Строка %1").arg(i + 1));
        }
    }

    for (int i = 0; i < m_colOrderList->count(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, i);
            item->setText(QString("Столбец %1").arg(i + 1));
        }
    }

    m_updating = false;

    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onWriteDirectionChanged(int index)
{
    Q_UNUSED(index);
    if (m_updating) return;
    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onReadDirectionChanged(int index)
{
    Q_UNUSED(index);
    if (m_updating) return;
    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onZigzagClicked()
{
    m_updating = true;
    for (int i = 0; i < m_writeDirectionCombos.size(); ++i) {
        m_writeDirectionCombos[i]->setCurrentIndex(i % 2);
    }
    m_updating = false;
    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onAllWriteLeftClicked()
{
    m_updating = true;
    for (auto combo : m_writeDirectionCombos) {
        combo->setCurrentIndex(0);
    }
    m_updating = false;
    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onAllWriteRightClicked()
{
    m_updating = true;
    for (auto combo : m_writeDirectionCombos) {
        combo->setCurrentIndex(1);
    }
    m_updating = false;
    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onAllReadTopClicked()
{
    m_updating = true;
    for (auto combo : m_readDirectionCombos) {
        combo->setCurrentIndex(0);
    }
    m_updating = false;
    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onAllReadBottomClicked()
{
    m_updating = true;
    for (auto combo : m_readDirectionCombos) {
        combo->setCurrentIndex(1);
    }
    m_updating = false;
    updateTablePreview();
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onRowOrderNormalize()
{
    m_updating = true;
    for (int i = 0; i < m_rowOrderList->count(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, i);
            item->setText(QString("Строка %1").arg(i + 1));
        }
    }
    m_updating = false;
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onRowOrderReverse()
{
    m_updating = true;
    QVector<int> indices;
    for (int i = 0; i < m_rowOrderList->count(); ++i) {
        indices.append(m_rowOrderList->item(i)->data(Qt::UserRole).toInt());
    }

    for (int i = 0; i < indices.size(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            int newIndex = indices[indices.size() - 1 - i];
            item->setData(Qt::UserRole, newIndex);
            item->setText(QString("Строка %1").arg(newIndex + 1));
        }
    }
    m_updating = false;
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onColumnOrderNormalize()
{
    m_updating = true;
    for (int i = 0; i < m_colOrderList->count(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, i);
            item->setText(QString("Столбец %1").arg(i + 1));
        }
    }
    m_updating = false;
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onColumnOrderReverse()
{
    m_updating = true;
    QVector<int> indices;
    for (int i = 0; i < m_colOrderList->count(); ++i) {
        indices.append(m_colOrderList->item(i)->data(Qt::UserRole).toInt());
    }

    for (int i = 0; i < indices.size(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            int newIndex = indices[indices.size() - 1 - i];
            item->setData(Qt::UserRole, newIndex);
            item->setText(QString("Столбец %1").arg(newIndex + 1));
        }
    }
    m_updating = false;
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onTabChanged(int index)
{
    if (index == 2) {
        updateTablePreview();
    }
}

void RouteCipherAdvancedWidget::onRowListChanged()
{
    if (m_updating) return;
    emit parametersChanged();
}

void RouteCipherAdvancedWidget::onColumnListChanged()
{
    if (m_updating) return;
    emit parametersChanged();
}

// ==================== ГЕТТЕРЫ ====================

int RouteCipherAdvancedWidget::getRows() const
{
    return m_autoSizeCheck->isChecked() ? 0 : m_currentRows;
}

int RouteCipherAdvancedWidget::getCols() const
{
    return m_autoSizeCheck->isChecked() ? 0 : m_currentCols;
}

QVector<Direction> RouteCipherAdvancedWidget::getWriteDirections() const
{
    QVector<Direction> dirs;
    for (int i = 0; i < m_currentRows && i < m_writeDirectionCombos.size(); ++i) {
        dirs.append(static_cast<Direction>(m_writeDirectionCombos[i]->currentData().toInt()));
    }
    return dirs;
}

QVector<Direction> RouteCipherAdvancedWidget::getReadDirections() const
{
    QVector<Direction> dirs;
    for (int i = 0; i < m_currentCols && i < m_readDirectionCombos.size(); ++i) {
        dirs.append(static_cast<Direction>(m_readDirectionCombos[i]->currentData().toInt()));
    }
    return dirs;
}

QVector<int> RouteCipherAdvancedWidget::getRowOrder() const
{
    QVector<int> order;
    int count = qMin(m_currentRows, m_rowOrderList->count());
    for (int i = 0; i < count; ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            order.append(item->data(Qt::UserRole).toInt() + 1);
        }
    }
    return order;
}

QVector<int> RouteCipherAdvancedWidget::getColumnOrder() const
{
    QVector<int> order;
    int count = qMin(m_currentCols, m_colOrderList->count());
    for (int i = 0; i < count; ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            order.append(item->data(Qt::UserRole).toInt() + 1);
        }
    }
    return order;
}

// ==================== СЕТТЕРЫ ====================

void RouteCipherAdvancedWidget::setRows(int rows)
{
    if (rows > 0) {
        m_autoSizeCheck->setChecked(false);
        m_rowsSpin->setValue(rows);
    } else {
        m_autoSizeCheck->setChecked(true);
    }
}

void RouteCipherAdvancedWidget::setCols(int cols)
{
    if (cols > 0) {
        m_autoSizeCheck->setChecked(false);
        m_colsSpin->setValue(cols);
    } else {
        m_autoSizeCheck->setChecked(true);
    }
}

void RouteCipherAdvancedWidget::setWriteDirections(const QVector<Direction>& dirs)
{
    m_updating = true;
    for (int i = 0; i < dirs.size() && i < m_writeDirectionCombos.size(); ++i) {
        int index = (dirs[i] == LEFT_TO_RIGHT) ? 0 : 1;
        m_writeDirectionCombos[i]->setCurrentIndex(index);
    }
    m_updating = false;
    updateTablePreview();
}

void RouteCipherAdvancedWidget::setReadDirections(const QVector<Direction>& dirs)
{
    m_updating = true;
    for (int i = 0; i < dirs.size() && i < m_readDirectionCombos.size(); ++i) {
        int index = (dirs[i] == TOP_TO_BOTTOM) ? 0 : 1;
        m_readDirectionCombos[i]->setCurrentIndex(index);
    }
    m_updating = false;
    updateTablePreview();
}

void RouteCipherAdvancedWidget::setRowOrder(const QVector<int>& order)
{
    m_updating = true;
    for (int i = 0; i < order.size() && i < m_rowOrderList->count(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, order[i] - 1);
            item->setText(QString("Строка %1").arg(order[i]));
        }
    }
    m_updating = false;
}

void RouteCipherAdvancedWidget::setColumnOrder(const QVector<int>& order)
{
    m_updating = true;
    for (int i = 0; i < order.size() && i < m_colOrderList->count(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, order[i] - 1);
            item->setText(QString("Столбец %1").arg(order[i]));
        }
    }
    m_updating = false;
}

// ==================== ВАЛИДАЦИЯ ====================

bool RouteCipherAdvancedWidget::validate(QString& errorMessage) const
{
    QSet<int> rowValues;
    for (int i = 0; i < m_currentRows && i < m_rowOrderList->count(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            int val = item->data(Qt::UserRole).toInt() + 1;
            if (rowValues.contains(val)) {
                errorMessage = QString("Порядок строк содержит повторяющееся значение %1").arg(val);
                return false;
            }
            if (val < 1 || val > m_currentRows) {
                errorMessage = QString("Значение %1 в порядке строк выходит за пределы 1..%2")
                                  .arg(val).arg(m_currentRows);
                return false;
            }
            rowValues.insert(val);
        }
    }

    QSet<int> colValues;
    for (int i = 0; i < m_currentCols && i < m_colOrderList->count(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            int val = item->data(Qt::UserRole).toInt() + 1;
            if (colValues.contains(val)) {
                errorMessage = QString("Порядок столбцов содержит повторяющееся значение %1").arg(val);
                return false;
            }
            if (val < 1 || val > m_currentCols) {
                errorMessage = QString("Значение %1 в порядке столбцов выходит за пределы 1..%2")
                                  .arg(val).arg(m_currentCols);
                return false;
            }
            colValues.insert(val);
        }
    }

    return true;
}

void RouteCipherAdvancedWidget::resetToDefault()
{
    onResetToDefault();
}

// ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

void RouteCipherAdvancedWidget::updateDirectionControlsState()
{
    for (int i = 0; i < m_writeDirectionCombos.size(); ++i) {
        bool enabled = (i < m_currentRows);
        QLayoutItem* labelItem = m_writeGrid->itemAtPosition(i, 0);
        QLayoutItem* comboItem = m_writeGrid->itemAtPosition(i, 1);
        if (labelItem) labelItem->widget()->setEnabled(enabled);
        if (comboItem) comboItem->widget()->setEnabled(enabled);
    }

    for (int i = 0; i < m_readDirectionCombos.size(); ++i) {
        bool enabled = (i < m_currentCols);
        QLayoutItem* labelItem = m_readGrid->itemAtPosition(i, 0);
        QLayoutItem* comboItem = m_readGrid->itemAtPosition(i, 1);
        if (labelItem) labelItem->widget()->setEnabled(enabled);
        if (comboItem) comboItem->widget()->setEnabled(enabled);
    }
}

void RouteCipherAdvancedWidget::updateOrderControlsState()
{
    for (int i = 0; i < m_rowOrderSpins.size(); ++i) {
        m_rowOrderSpins[i]->setVisible(i < m_currentRows);
    }

    for (int i = 0; i < m_colOrderSpins.size(); ++i) {
        m_colOrderSpins[i]->setVisible(i < m_currentCols);
    }
}

void RouteCipherAdvancedWidget::syncDirectionsFromTable()
{
}

void RouteCipherAdvancedWidget::syncOrdersFromLists()
{
    m_updating = true;

    for (int i = 0; i < m_rowOrderList->count() && i < m_rowOrderSpins.size(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            int rowIndex = item->data(Qt::UserRole).toInt();
            m_rowOrderSpins[i]->setValue(rowIndex + 1);
        }
    }

    for (int i = 0; i < m_colOrderList->count() && i < m_colOrderSpins.size(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            int colIndex = item->data(Qt::UserRole).toInt();
            m_colOrderSpins[i]->setValue(colIndex + 1);
        }
    }

    m_updating = false;
}

void RouteCipherAdvancedWidget::updateRowOrderSpins()
{
    for (int i = 0; i < m_rowOrderSpins.size() && i < m_rowOrderList->count(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            m_rowOrderSpins[i]->setValue(item->data(Qt::UserRole).toInt() + 1);
        }
    }
}

void RouteCipherAdvancedWidget::updateColumnOrderSpins()
{
    for (int i = 0; i < m_colOrderSpins.size() && i < m_colOrderList->count(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            m_colOrderSpins[i]->setValue(item->data(Qt::UserRole).toInt() + 1);
        }
    }
}

void RouteCipherAdvancedWidget::onRowSpinChanged(int value)
{
    if (m_updating) return;

    Q_UNUSED(value);
    // Здесь можно добавить логику для синхронизации спинбоксов со списком
    // Например:
    m_updating = true;

    // Обновляем список на основе значений спинбоксов
    for (int i = 0; i < m_rowOrderSpins.size() && i < m_rowOrderList->count(); ++i) {
        int spinValue = m_rowOrderSpins[i]->value();
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, spinValue - 1);
            item->setText(QString("Строка %1").arg(spinValue));
        }
    }

    m_updating = false;
    emit parametersChanged();
}
void RouteCipherAdvancedWidget::onColSpinChanged(int value)
{
    if (m_updating) return;

    Q_UNUSED(value);
    m_updating = true;

    for (int i = 0; i < m_colOrderSpins.size() && i < m_colOrderList->count(); ++i) {
        int spinValue = m_colOrderSpins[i]->value();
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            item->setData(Qt::UserRole, spinValue - 1);
            item->setText(QString("Столбец %1").arg(spinValue));
        }
    }

    m_updating = false;
    emit parametersChanged();
}
void RouteCipherAdvancedWidget::onRowsChanged(int value)
{
    if (m_updating) return;
    m_updating = true;

    m_currentRows = value;

    // Обновляем видимость комбобоксов для строк
    for (int i = 0; i < m_writeDirectionCombos.size(); ++i) {
        bool visible = i < value;
        if (i < m_writeGrid->rowCount()) {
            QLayoutItem* labelItem = m_writeGrid->itemAtPosition(i, 0);
            QLayoutItem* comboItem = m_writeGrid->itemAtPosition(i, 1);
            if (labelItem && labelItem->widget()) {
                labelItem->widget()->setVisible(visible);
                labelItem->widget()->setEnabled(visible);
            }
            if (comboItem && comboItem->widget()) {
                comboItem->widget()->setVisible(visible);
                comboItem->widget()->setEnabled(visible);
            }
        }
    }

    // Обновляем видимость элементов в списке порядка строк
    for (int i = 0; i < m_rowOrderList->count(); ++i) {
        QListWidgetItem* item = m_rowOrderList->item(i);
        if (item) {
            item->setHidden(i >= value);
        }
    }

    // Обновляем диапазон спинбоксов порядка строк
    for (int i = 0; i < m_rowOrderSpins.size(); ++i) {
        if (i < value) {
            m_rowOrderSpins[i]->setVisible(true);
            m_rowOrderSpins[i]->setMaximum(value);
        } else {
            m_rowOrderSpins[i]->setVisible(false);
        }
    }

    // Обновляем информацию о размере
    if (!m_autoSizeCheck->isChecked()) {
        m_sizeInfoLabel->setText(QString("Фиксированный размер: %1×%2")
                                 .arg(m_currentRows).arg(m_currentCols));
    }

    updateTablePreview();
    emit parametersChanged();

    m_updating = false;
}

void RouteCipherAdvancedWidget::onColsChanged(int value)
{
    if (m_updating) return;
    m_updating = true;

    m_currentCols = value;

    // Обновляем видимость комбобоксов для столбцов
    for (int i = 0; i < m_readDirectionCombos.size(); ++i) {
        bool visible = i < value;
        if (i < m_readGrid->rowCount()) {
            QLayoutItem* labelItem = m_readGrid->itemAtPosition(i, 0);
            QLayoutItem* comboItem = m_readGrid->itemAtPosition(i, 1);
            if (labelItem && labelItem->widget()) {
                labelItem->widget()->setVisible(visible);
                labelItem->widget()->setEnabled(visible);
            }
            if (comboItem && comboItem->widget()) {
                comboItem->widget()->setVisible(visible);
                comboItem->widget()->setEnabled(visible);
            }
        }
    }

    // Обновляем видимость элементов в списке порядка столбцов
    for (int i = 0; i < m_colOrderList->count(); ++i) {
        QListWidgetItem* item = m_colOrderList->item(i);
        if (item) {
            item->setHidden(i >= value);
        }
    }

    // Обновляем диапазон спинбоксов порядка столбцов
    for (int i = 0; i < m_colOrderSpins.size(); ++i) {
        if (i < value) {
            m_colOrderSpins[i]->setVisible(true);
            m_colOrderSpins[i]->setMaximum(value);
        } else {
            m_colOrderSpins[i]->setVisible(false);
        }
    }

    // Обновляем информацию о размере
    if (!m_autoSizeCheck->isChecked()) {
        m_sizeInfoLabel->setText(QString("Фиксированный размер: %1×%2")
                                 .arg(m_currentRows).arg(m_currentCols));
    }

    updateTablePreview();
    emit parametersChanged();

    m_updating = false;
}

// Добавьте этот метод в routecipherwidget.cpp
QVariantMap RouteCipherAdvancedWidget::getParameters() const
{
    QVariantMap params;

    // Размеры таблицы
    params["rows"] = getRows();
    params["cols"] = getCols();

    // Направления записи
    QVariantList writeDirs;
    QVector<Direction> writeVec = getWriteDirections();
    for (Direction d : writeVec) {
        writeDirs.append(static_cast<int>(d));
    }
    params["writeDirections"] = writeDirs;

    // Направления чтения
    QVariantList readDirs;
    QVector<Direction> readVec = getReadDirections();
    for (Direction d : readVec) {
        readDirs.append(static_cast<int>(d));
    }
    params["readDirections"] = readDirs;

    // Порядок строк
    QVariantList rowOrderList;
    QVector<int> rowVec = getRowOrder();
    for (int v : rowVec) {
        rowOrderList.append(v);
    }
    params["rowOrder"] = rowOrderList;

    // Порядок столбцов
    QVariantList colOrderList;
    QVector<int> colVec = getColumnOrder();
    for (int v : colVec) {
        colOrderList.append(v);
    }
    params["columnOrder"] = colOrderList;

    return params;
}

void RouteCipherAdvancedWidget::setPreviewText(const QString& text)
{
    m_previewText = text;
    updateTablePreview();  // Обновить предпросмотр с новым текстом
}
