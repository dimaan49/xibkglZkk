#include "librarywindow.h"
#include "cipherfactory.h"
#include <QLabel>
#include <QScrollArea>
#include <QGroupBox>
#include <QCheckBox>
#include <QPushButton>
#include <QScrollBar>

LibraryWindow::LibraryWindow(QWidget* parent)
    : QDialog(parent)
    , m_splitter(nullptr)
    , m_cipherList(nullptr)
    , m_infoEdit(nullptr)
    , m_searchEdit(nullptr)
{
    setupUI();
    loadCiphers();
    setWindowTitle("Библиотека шифров");
    resize(800, 600);
}

LibraryWindow::~LibraryWindow() {}

void LibraryWindow::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    m_splitter = new QSplitter(Qt::Horizontal, this);

    // Левая панель - фильтр и список
    QWidget* leftPanel = new QWidget();
    QVBoxLayout* leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setSpacing(5);
    leftLayout->setContentsMargins(10, 10, 5, 10);

    // Заголовок фильтра
    QLabel* filterLabel = new QLabel("Категории шифров:");
    filterLabel->setStyleSheet("font-weight: bold; padding: 5px 0;");
    leftLayout->addWidget(filterLabel);

    // Кнопки выбрать все/снять все
    QHBoxLayout* filterButtonsLayout = new QHBoxLayout();
    QPushButton* selectAllBtn = new QPushButton("Все");
    QPushButton* clearAllBtn = new QPushButton("Снять");
    selectAllBtn->setFixedHeight(25);
    clearAllBtn->setFixedHeight(25);
    connect(selectAllBtn, &QPushButton::clicked, this, &LibraryWindow::onSelectAll);
    connect(clearAllBtn, &QPushButton::clicked, this, &LibraryWindow::onClearAll);
    filterButtonsLayout->addWidget(selectAllBtn);
    filterButtonsLayout->addWidget(clearAllBtn);
    filterButtonsLayout->addStretch();
    leftLayout->addLayout(filterButtonsLayout);

    // Чекбоксы категорий
    QScrollArea* scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* scrollContent = new QWidget();
    QVBoxLayout* scrollLayout = new QVBoxLayout(scrollContent);
    scrollLayout->setSpacing(3);
    scrollLayout->setContentsMargins(0, 0, 0, 0);

    QList<CipherCategory> categories = {
        CipherCategory::KeyExchange,
        CipherCategory::DigitalSignature,
        CipherCategory::Asymmetric,
        CipherCategory::Combinatorial,
        CipherCategory::Stream,
        CipherCategory::Gamma,
        CipherCategory::Permutation,
        CipherCategory::BlockSubstitution,
        CipherCategory::Polyalphabetic,
        CipherCategory::Monoalphabetic
    };

    for (CipherCategory cat : categories) {
        QCheckBox* cb = new QCheckBox(CipherFactory::getCategoryName(cat));
        cb->setProperty("category", static_cast<int>(cat));
        cb->setChecked(false);
        connect(cb, &QCheckBox::stateChanged, this, &LibraryWindow::onFilterChanged);
        m_categoryCheckboxes.append(cb);
        scrollLayout->addWidget(cb);
    }
    scrollLayout->addStretch();

    scrollArea->setWidget(scrollContent);
    leftLayout->addWidget(scrollArea);

    // Поиск
    QLabel* searchLabel = new QLabel("Поиск:");
    searchLabel->setStyleSheet("font-weight: bold; padding: 10px 0 5px 0;");
    leftLayout->addWidget(searchLabel);

    m_searchEdit = new QLineEdit();
    m_searchEdit->setPlaceholderText("Введите название...");
    m_searchEdit->setClearButtonEnabled(true);
    connect(m_searchEdit, &QLineEdit::textChanged, this, &LibraryWindow::onFilterChanged);
    leftLayout->addWidget(m_searchEdit);

    // Список шифров
    QLabel* listLabel = new QLabel("Список шифров:");
    listLabel->setStyleSheet("font-weight: bold; padding: 10px 0 5px 0;");
    leftLayout->addWidget(listLabel);

    m_cipherList = new QListWidget();
    m_cipherList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_cipherList->verticalScrollBar()->setSingleStep(20);
    connect(m_cipherList, &QListWidget::currentRowChanged, this, &LibraryWindow::onCipherSelected);
    leftLayout->addWidget(m_cipherList, 1);

    // Правая панель - информация
    QWidget* rightPanel = new QWidget();
    QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(5, 10, 10, 10);

    QLabel* infoLabel = new QLabel("Информация о шифре:");
    infoLabel->setStyleSheet("font-weight: bold; padding: 5px 0;");
    rightLayout->addWidget(infoLabel);

    m_infoEdit = new QTextEdit();
    m_infoEdit->setReadOnly(true);
    rightLayout->addWidget(m_infoEdit, 1);

    m_splitter->addWidget(leftPanel);
    m_splitter->addWidget(rightPanel);
    m_splitter->setSizes(QList<int>() << 300 << 500);

    mainLayout->addWidget(m_splitter);
}

void LibraryWindow::loadCiphers()
{
    m_allCipherNames.clear();
    m_allCipherDescriptions.clear();

    QStringList names = CipherFactory::instance().displayNames();
    for (const QString& name : names) {
        m_allCipherNames.append(name);
        int id = CipherFactory::instance().idFromDisplayName(name);
        m_allCipherDescriptions.append(CipherFactory::instance().cipherDescription(id));
    }

    applyFilter();
}

void LibraryWindow::applyFilter()
{
    m_cipherList->clear();

    // Собираем выбранные категории
    QList<CipherCategory> selectedCategories;
    for (QCheckBox* cb : m_categoryCheckboxes) {
        if (cb->isChecked()) {
            selectedCategories.append(static_cast<CipherCategory>(cb->property("category").toInt()));
        }
    }

    QString searchText = m_searchEdit->text().trimmed().toLower();

    for (int i = 0; i < m_allCipherNames.size(); ++i) {
        QString name = m_allCipherNames[i];
        int id = CipherFactory::instance().idFromDisplayName(name);
        CipherCategory cat = CipherFactory::instance().cipherCategory(id);

        // Проверка категории
        if (!selectedCategories.isEmpty() && !selectedCategories.contains(cat)) {
            continue;
        }

        // Проверка поиска
        if (!searchText.isEmpty() && !name.toLower().contains(searchText)) {
            continue;
        }

        m_cipherList->addItem(name);
    }

    if (m_cipherList->count() > 0) {
        m_cipherList->setCurrentRow(0);
    }
}

void LibraryWindow::onFilterChanged()
{
    applyFilter();
}

void LibraryWindow::onCipherSelected(int index)
{
    if (index < 0 || index >= m_cipherList->count()) return;

    QString selectedName = m_cipherList->item(index)->text();
    int nameIndex = m_allCipherNames.indexOf(selectedName);

    if (nameIndex >= 0) {
        int id = CipherFactory::instance().idFromDisplayName(selectedName);
        QString info;
        info += "Название: " + selectedName + "\n\n";
        info += "Категория: " + CipherFactory::getCategoryName(CipherFactory::instance().cipherCategory(id)) + "\n\n";
        info += "Описание:\n" + m_allCipherDescriptions[nameIndex];
        m_infoEdit->setPlainText(info);
    }
}

void LibraryWindow::onSelectAll()
{
    for (QCheckBox* cb : m_categoryCheckboxes) {
        cb->setChecked(false);
    }
}

void LibraryWindow::onClearAll()
{
    for (QCheckBox* cb : m_categoryCheckboxes) {
        cb->setChecked(false);
    }
}
