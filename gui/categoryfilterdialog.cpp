#include "categoryfilterdialog.h".h"
#include <QHBoxLayout>
#include <QFrame>

CategoryFilterDialog::CategoryFilterDialog(QWidget* parent)
    : QDialog(parent)
{
    setupUI();
    setWindowTitle("Фильтр шифров по категориям");
    setMinimumWidth(280);
    setMaximumWidth(350);
    setModal(true);
}

void CategoryFilterDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(10);

    // Заголовок
    QLabel* titleLabel = new QLabel("Выберите категории шифров для отображения:");
    titleLabel->setStyleSheet("font-weight: bold; margin-bottom: 5px;");
    titleLabel->setWordWrap(true);
    mainLayout->addWidget(titleLabel);

    // Кнопки управления
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    m_selectAllButton = new QPushButton("✓ Выбрать всё");
    m_clearAllButton = new QPushButton("✗ Снять всё");
    m_selectAllButton->setFixedHeight(28);
    m_clearAllButton->setFixedHeight(28);

    connect(m_selectAllButton, &QPushButton::clicked, this, [this]() { selectAllCategories(true); });
    connect(m_clearAllButton, &QPushButton::clicked, this, [this]() { selectAllCategories(false); });

    buttonLayout->addWidget(m_selectAllButton);
    buttonLayout->addWidget(m_clearAllButton);
    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Разделитель
    QFrame* line = new QFrame();
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    mainLayout->addWidget(line);

    // Скроллируемая область с чекбоксами
    QScrollArea* scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setMinimumHeight(300);
    scrollArea->setMaximumHeight(400);

    QWidget* scrollContent = new QWidget();
    QVBoxLayout* scrollLayout = new QVBoxLayout(scrollContent);
    scrollLayout->setSpacing(8);
    scrollLayout->setContentsMargins(5, 5, 5, 5);

    // Все категории
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
        CipherCategory::Monoalphabetic,
    };

    for (CipherCategory cat : categories) {
        QCheckBox* cb = createCategoryCheckbox(cat);
        cb->setChecked(true);
        m_checkboxes[cat] = cb;
        scrollLayout->addWidget(cb);
    }

    scrollLayout->addStretch();
    scrollArea->setWidget(scrollContent);
    mainLayout->addWidget(scrollArea);

    // Кнопки OK/Cancel
    m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(m_buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(m_buttonBox);
}

QCheckBox* CategoryFilterDialog::createCategoryCheckbox(CipherCategory category)
{
    QString name = CipherFactory::getCategoryName(category);
    QCheckBox* cb = new QCheckBox(name);
    cb->setStyleSheet("QCheckBox { padding: 3px; }");
    return cb;
}

QList<CipherCategory> CategoryFilterDialog::selectedCategories() const
{
    QList<CipherCategory> result;
    for (auto it = m_checkboxes.begin(); it != m_checkboxes.end(); ++it) {
        if (it.value()->isChecked()) {
            result.append(it.key());
        }
    }
    return result;
}

void CategoryFilterDialog::setSelectedCategories(const QList<CipherCategory>& categories)
{
    // Сначала снимаем все
    for (auto cb : m_checkboxes) {
        cb->setChecked(false);
    }
    // Затем отмечаем выбранные
    for (CipherCategory cat : categories) {
        if (m_checkboxes.contains(cat)) {
            m_checkboxes[cat]->setChecked(true);
        }
    }
}

void CategoryFilterDialog::selectAllCategories(bool selected)
{
    for (auto cb : m_checkboxes) {
        cb->setChecked(selected);
    }
}
