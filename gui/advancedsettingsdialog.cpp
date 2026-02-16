#include "advancedsettingsdialog.h"
#include "cipherwidgetfactory.h"
#include "stylemanager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QCloseEvent>
#include <QResizeEvent>
#include <QStyle>
#include <QApplication>
#include <QDebug>

AdvancedSettingsDialog::AdvancedSettingsDialog(const QString& cipherId, const QString& cipherName,
                                             QWidget* parent)
    : QDialog(parent, Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowTitleHint)
    , m_cipherId(cipherId)
    , m_cipherName(cipherName)
    , m_mainLayout(nullptr)
    , m_titleLabel(nullptr)
    , m_contentWidget(nullptr)
    , m_contentLayout(nullptr)
    , m_buttonBox(nullptr)
{
    setModal(true);
    setObjectName("AdvancedSettingsDialog");
    setupUI();
    createAdvancedWidgets();
}

AdvancedSettingsDialog::~AdvancedSettingsDialog()
{
    m_advancedWidgets.clear();
    qDebug() << "AdvancedSettingsDialog destroyed for cipher:" << m_cipherName;
}

void AdvancedSettingsDialog::setupUI()
{
    setWindowTitle(tr("Расширенные настройки - %1").arg(m_cipherName));
    setMinimumWidth(1000);
    setMinimumHeight(600);
    setModal(true);
    setObjectName("AdvancedSettingsDialog");

    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(15);
    m_mainLayout->setContentsMargins(20, 20, 20, 20);

    // Заголовок
    m_titleLabel = new QLabel(tr("⚙ Расширенные параметры шифра"));
    m_titleLabel->setObjectName("dialogTitle");
    m_titleLabel->setStyleSheet(
        "font-size: 16px; "
        "font-weight: bold; "
        "padding: 5px; "
        "border-bottom: 2px solid #3e3e3e;"
    );
    m_mainLayout->addWidget(m_titleLabel);

    // Контент (будет создан в createAdvancedWidgets)
    m_contentWidget = nullptr;
    m_contentLayout = nullptr;

    // Кнопки
    m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    m_buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Применить"));
    m_buttonBox->button(QDialogButtonBox::Cancel)->setText(tr("Отмена"));
    m_buttonBox->button(QDialogButtonBox::Ok)->setObjectName("dialogOkButton");
    m_buttonBox->button(QDialogButtonBox::Cancel)->setObjectName("dialogCancelButton");

    connect(m_buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    m_mainLayout->addWidget(m_buttonBox);
}

void AdvancedSettingsDialog::createAdvancedWidgets()
{
    // Удаляем старый contentWidget целиком
    if (m_contentWidget) {
        delete m_contentWidget;
        m_contentWidget = nullptr;
        m_contentLayout = nullptr;
    }

    // Создаем новый
    m_contentWidget = new QWidget(this);
    m_contentWidget->setObjectName("advancedContentWidget");
    m_contentLayout = new QVBoxLayout(m_contentWidget);
    m_contentLayout->setSpacing(10);
    m_contentLayout->setContentsMargins(0, 0, 0, 0);

    // Добавляем в mainLayout (перед кнопками)
    m_mainLayout->insertWidget(1, m_contentWidget, 1);

    // Очищаем хранилище
    m_advancedWidgets.clear();

    // Создаем виджеты
    CipherWidgetFactory::instance().createAdvancedWidgets(
        m_cipherId,
        m_contentWidget,
        m_contentLayout,
        m_advancedWidgets
    );

    // Заглушка
    if (m_advancedWidgets.isEmpty()) {
        QLabel* noWidgetsLabel = new QLabel(tr("Для данного шифра нет расширенных настроек."), m_contentWidget);
        noWidgetsLabel->setObjectName("noWidgetsLabel");
        noWidgetsLabel->setStyleSheet("color: #888; font-style: italic; padding: 20px;");
        noWidgetsLabel->setAlignment(Qt::AlignCenter);
        m_contentLayout->addWidget(noWidgetsLabel);
        m_advancedWidgets["noWidgetsLabel"] = noWidgetsLabel;
    }
}

QVariantMap AdvancedSettingsDialog::getSettings() const
{
    return CipherWidgetFactory::collectValues(m_advancedWidgets);
}

void AdvancedSettingsDialog::setSettings(const QVariantMap& settings)
{
    m_initialSettings = settings;
    CipherWidgetFactory::updateWidgets(m_advancedWidgets, settings);
}

void AdvancedSettingsDialog::reject()
{
    qDebug() << "AdvancedSettingsDialog: reject() called for" << m_cipherName;
    QDialog::reject();
}

void AdvancedSettingsDialog::accept()
{
    qDebug() << "AdvancedSettingsDialog: accept() called for" << m_cipherName;
    QDialog::accept();
}

void AdvancedSettingsDialog::closeEvent(QCloseEvent* event)
{
    qDebug() << "AdvancedSettingsDialog: closeEvent() for" << m_cipherName;
    reject();
    event->accept();
}
