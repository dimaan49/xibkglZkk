#include "mainwindow.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "formatter.h"
#include "stylemanager.h"
#include "advancedsettingsdialog.h"
#include "categoryfilterdialog.h"

#include <iostream>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QComboBox>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QDebug>
#include <QSpinBox>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QLineEdit>
#include <QPropertyAnimation>
#include <QGraphicsDropShadowEffect>
#include <QSequentialAnimationGroup>
#include <QParallelAnimationGroup>

// ==================== AnimatedButton Class Definition ====================
class AnimatedButton : public QPushButton
{
    Q_PROPERTY(int borderRadius READ borderRadius WRITE setBorderRadius)

public:
    explicit AnimatedButton(const QString& text, QWidget* parent = nullptr)
        : QPushButton(text, parent)
    {
        setCursor(Qt::PointingHandCursor);
        m_hoverAnimation = new QPropertyAnimation(this, "borderRadius");
        m_hoverAnimation->setDuration(150);
        m_hoverAnimation->setEasingCurve(QEasingCurve::OutCubic);
    }

    ~AnimatedButton() {
        delete m_hoverAnimation;
    }

    int borderRadius() const { return m_borderRadius; }

    void setBorderRadius(int radius) {
        m_borderRadius = radius;
        QString style = QString(
            "QPushButton {"
            "    border-radius: %1px;"
            "}"
        ).arg(radius);
        setStyleSheet(style);
    }

protected:
    void enterEvent(QEnterEvent* event) override {
        QPushButton::enterEvent(event);
        m_hoverAnimation->stop();
        m_hoverAnimation->setStartValue(borderRadius());
        m_hoverAnimation->setEndValue(10);
        m_hoverAnimation->start();
    }

    void leaveEvent(QEvent* event) override {
        QPushButton::leaveEvent(event);
        m_hoverAnimation->stop();
        m_hoverAnimation->setStartValue(borderRadius());
        m_hoverAnimation->setEndValue(6);
        m_hoverAnimation->start();
    }

private:
    int m_borderRadius = 6;
    QPropertyAnimation* m_hoverAnimation;
};

// ==================== MainWindow Implementation ====================
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_cipherComboBox(nullptr)
    , themeComboBox(nullptr)
    , inputTextEdit(nullptr)
    , outputTextEdit(nullptr)
    , debugConsole(nullptr)
    , encryptButton(nullptr)
    , decryptButton(nullptr)
    , clearButton(nullptr)
    , statusLabel(nullptr)
    , parametersGroup(nullptr)
    , m_advancedSettingsButton(nullptr)
    , m_statusResetTimer(nullptr)
    , parametersLayout(nullptr)
    , m_filterDialog(nullptr)
    , m_filterButton(nullptr)
    , m_analysisWindow(nullptr)
    , m_libraryWindow(nullptr)
{
    setupUI();
    setupCiphers();
    setupThemeSelector();

    // Применяем тему по умолчанию
    StyleManager::applyTheme(this, StyleManager::THEME_CYBER_MIDNIGHT);

    setWindowTitle("MospolyCrypt - Криптографическое приложение");
    resize(900, 700);
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUI()
{
    // Центральный виджет с эффектом тени
    QWidget *centralWidget = new QWidget(this);
    QGraphicsDropShadowEffect* shadowEffect = new QGraphicsDropShadowEffect();
    shadowEffect->setBlurRadius(15);
    shadowEffect->setColor(QColor(0, 0, 0, 80));
    shadowEffect->setOffset(0, 2);
    centralWidget->setGraphicsEffect(shadowEffect);

    setCentralWidget(centralWidget);

    // Основной layout с отступами
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // 1. Верхняя панель: Выбор шифра + темы
    QHBoxLayout *topPanelLayout = new QHBoxLayout();

    // Логотип/заголовок
    QLabel *logoLabel = new QLabel("🔒 MospolyCryp");
    logoLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: #00c896;");
    topPanelLayout->addWidget(logoLabel);
    topPanelLayout->addStretch();

    // Меню действий
    m_menuBar = new QMenuBar(this);
    m_menuBar->setStyleSheet("QMenuBar { background-color: transparent; }");

    m_actionsMenu = m_menuBar->addMenu("Действия");

    QAction* analysisAction = m_actionsMenu->addAction("Анализ");
    QAction* libraryAction = m_actionsMenu->addAction("Библиотека");

    connect(analysisAction, &QAction::triggered, this, &MainWindow::onAnalysisWindowOpen);
    connect(libraryAction, &QAction::triggered, this, &MainWindow::onLibraryWindowOpen);

    topPanelLayout->addWidget(m_menuBar);
    topPanelLayout->addStretch();

    // Выбор темы
    QLabel *themeLabel = new QLabel("Тема:");
    themeComboBox = new QComboBox();
    themeComboBox->addItem("Cyber Midnight");
    themeComboBox->addItem("Dark Professional");
    themeComboBox->addItem("Reliable Orange");
    themeComboBox->setObjectName("themeSelector");
    connect(themeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onThemeChanged);

    topPanelLayout->addWidget(themeLabel);
    topPanelLayout->addWidget(themeComboBox);
    topPanelLayout->addSpacing(20);

    // Выбор шифра
    QLabel *cipherLabel = new QLabel("Шифр:");

    // Контейнер для комбобокса и кнопки фильтра
    QWidget* cipherContainer = new QWidget();
    QHBoxLayout* cipherContainerLayout = new QHBoxLayout(cipherContainer);
    cipherContainerLayout->setContentsMargins(0, 0, 0, 0);
    cipherContainerLayout->setSpacing(8);

    // Комбобокс с шифрами
    m_cipherComboBox = new QComboBox(cipherContainer);
    m_cipherComboBox->setMinimumWidth(250);
    m_cipherComboBox->setObjectName("cipherSelector");
    m_cipherComboBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);


    // Кнопка фильтра
    m_filterButton = new QPushButton("🔧 Фильтр", cipherContainer);
    m_filterButton->setObjectName("filterButton");
    m_filterButton->setToolTip("Настроить фильтрацию шифров по категориям");
    m_filterButton->setCursor(Qt::PointingHandCursor);
    m_filterButton->setFixedHeight(28);
    m_filterButton->setFixedWidth(80);

    cipherContainerLayout->addWidget(m_cipherComboBox, 1);
    cipherContainerLayout->addWidget(m_filterButton);

    topPanelLayout->addWidget(cipherLabel);
    topPanelLayout->addWidget(cipherContainer);

    // Подключаем кнопку фильтра
    connect(m_filterButton, &QPushButton::clicked, this, &MainWindow::onFilterButtonClicked);

    // 2. Панель параметров
    parametersGroup = new QGroupBox("Параметры шифра");
    parametersLayout = new QVBoxLayout(parametersGroup);
    parametersLayout->setSpacing(8);
    parametersLayout->setContentsMargins(10, 15, 10, 10);

    // Создаем горизонтальный layout для заголовка
    QHBoxLayout* parametersHeaderLayout = new QHBoxLayout();

    // Кнопка расширенных настроек справа
    m_advancedSettingsButton = new QPushButton("⚙ Расширенные", parametersGroup);
    m_advancedSettingsButton->setObjectName("advancedSettingsButton");
    m_advancedSettingsButton->setToolTip("Открыть расширенные настройки шифра\n"
                                         "Дополнительные параметры и режимы работы");
    m_advancedSettingsButton->setCursor(Qt::PointingHandCursor);
    m_advancedSettingsButton->setMinimumHeight(28);
    m_advancedSettingsButton->setMinimumWidth(120);
    m_advancedSettingsButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); // Фиксированный размер

    // Сначала добавляем место для описания (будет добавляться динамически)
    // Просто создаем пустой layout, куда потом добавится описание

    // Добавляем кнопку в header layout (справа)
    parametersHeaderLayout->addStretch(); // Растяжение слева от кнопки
    parametersHeaderLayout->addWidget(m_advancedSettingsButton);

    // Вставляем header layout в начало parametersLayout
    parametersLayout->insertLayout(0, parametersHeaderLayout);


    // Эффект стекла для группы
    QGraphicsDropShadowEffect* groupShadow = new QGraphicsDropShadowEffect();
    groupShadow->setBlurRadius(10);
    groupShadow->setColor(QColor(0, 150, 255, 30));
    groupShadow->setOffset(0, 3);
    parametersGroup->setGraphicsEffect(groupShadow);

    // 3. Ввод текста
    QGroupBox *inputGroup = new QGroupBox("📝 Входной текст");
    QVBoxLayout *inputLayout = new QVBoxLayout();
    inputTextEdit = new QTextEdit();
    inputTextEdit->setObjectName("inputText");
    inputTextEdit->setPlaceholderText("Введите текст для шифрования/дешифрования...");
    inputTextEdit->setText("ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК");
    inputTextEdit->setAcceptRichText(false);
    inputLayout->addWidget(inputTextEdit);

    // Кнопка очистки ввода
    QHBoxLayout *inputToolsLayout = new QHBoxLayout();
    clearInputButton = new QPushButton("🗑️ Очистить");
    clearInputButton->setObjectName("clearInputButton");
    clearInputButton->setToolTip("Очистить поле ввода");
    clearInputButton->setMaximumWidth(100);
    inputToolsLayout->addStretch();
    inputToolsLayout->addWidget(clearInputButton);
    inputLayout->addLayout(inputToolsLayout);

    inputGroup->setLayout(inputLayout);

    // 5. Вывод результата
    QGroupBox *outputGroup = new QGroupBox("📊 Результат");
    QVBoxLayout *outputLayout = new QVBoxLayout();
    outputTextEdit = new QTextEdit();
    outputTextEdit->setObjectName("outputText");
    outputTextEdit->setReadOnly(true);
    outputTextEdit->setPlaceholderText("Здесь появится результат...");
    outputLayout->addWidget(outputTextEdit);

    // Кнопка очистки вывода
    QHBoxLayout *outputToolsLayout = new QHBoxLayout();
    clearOutputButton = new QPushButton("🗑️ Очистить");
    clearOutputButton->setObjectName("clearOutputButton");
    clearOutputButton->setToolTip("Очистить поле вывода");
    clearOutputButton->setMaximumWidth(100);
    outputToolsLayout->addStretch();
    outputToolsLayout->addWidget(clearOutputButton);
    outputLayout->addLayout(outputToolsLayout);

    outputGroup->setLayout(outputLayout);

    // 4. Кнопки действий (вертикальный контейнер)
    QWidget *buttonContainer = new QWidget();
    QVBoxLayout *buttonLayout = new QVBoxLayout(buttonContainer);
    buttonLayout->setSpacing(8);
    buttonLayout->setContentsMargins(10, 0, 10, 0);
    buttonLayout->setAlignment(Qt::AlignCenter);

    // Шифровать
    encryptButton = new AnimatedButton("🔐 Шифровать", this);
    encryptButton->setObjectName("encryptButton");
    encryptButton->setMinimumSize(120, 40);
    encryptButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    // Кнопка "Поменять"
    QPushButton *swapButton = new QPushButton("↕ Поменять", this);
    swapButton->setObjectName("swapButton");
    swapButton->setToolTip("Поменять местами входной и выходной текст");
    swapButton->setMinimumSize(120, 40);
    swapButton->setMaximumSize(120, 40);

    // Дешифровать
    decryptButton = new AnimatedButton("🔓 Расшифровать", this);
    decryptButton->setObjectName("decryptButton");
    decryptButton->setMinimumSize(120, 40);
    decryptButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    // текст по умолчанию
    QPushButton *defaultTextButton = new QPushButton("📝 Пример", this);
    defaultTextButton->setObjectName("defaultTextButton");
    defaultTextButton->setToolTip("Вставить пример текста");
    defaultTextButton->setMinimumSize(120, 40);
    defaultTextButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    // Очистить всё
    clearButton = new AnimatedButton("🗑️ Очистить всё", this);
    clearButton->setObjectName("clearButton");
    clearButton->setMinimumSize(120, 40);
    clearButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    // Добавляем кнопки вертикально
    buttonLayout->addWidget(encryptButton);
    buttonLayout->addWidget(swapButton);
    buttonLayout->addWidget(decryptButton);
    buttonLayout->addWidget(defaultTextButton);
    buttonLayout->addWidget(clearButton);
    buttonLayout->addStretch();

    // Создаем горизонтальный контейнер для ввода, кнопок и вывода
    QWidget *inputOutputContainer = new QWidget();
    QHBoxLayout *horizontalLayout = new QHBoxLayout(inputOutputContainer);
    horizontalLayout->setSpacing(15);
    horizontalLayout->setContentsMargins(0, 0, 0, 0);

    // Добавляем ввод, кнопки и вывод в горизонтальный layout
    horizontalLayout->addWidget(inputGroup, 1);
    horizontalLayout->addWidget(buttonContainer, 0);
    horizontalLayout->addWidget(outputGroup, 1);

    // 6. Большое окно логов
    logWindow = new LogWindow(this);

    // 7. Консоль для логов
    QGroupBox *consoleGroup = new QGroupBox("📋 Журнал операций");
    QVBoxLayout *consoleLayout = new QVBoxLayout(consoleGroup);
    consoleLayout->setSpacing(5);
    consoleLayout->setContentsMargins(5, 5, 5, 5);

    debugConsole = new QTextEdit();
    debugConsole->setReadOnly(true);
    debugConsole->setObjectName("console");
    debugConsole->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    consoleLayout->addWidget(debugConsole);

    // ПАНЕЛЬ КНОПОК ЛОГА
    QHBoxLayout *consoleToolsLayout = new QHBoxLayout();

    // Кнопка для открытия подробного лога
    showLogButton = new QPushButton("📋 Подробный лог");
    showLogButton->setObjectName("logButton");
    showLogButton->setToolTip("Открыть подробный журнал операций");
    showLogButton->setMaximumWidth(120);

    // Кнопка очистки лога
    clearLogButton = new QPushButton("🗑️ Очистить лог");
    clearLogButton->setObjectName("logButton");
    clearLogButton->setToolTip("Очистить журнал операций");
    clearLogButton->setMaximumWidth(120);

    consoleToolsLayout->addStretch();
    consoleToolsLayout->addWidget(clearLogButton);
    consoleToolsLayout->addWidget(showLogButton);

    consoleLayout->addLayout(consoleToolsLayout);
    consoleGroup->setLayout(consoleLayout);

    // 8. Статусная панель
    statusLabel = new QLabel("⚡ Готов к работе. Выберите шифр из списка.");
    statusLabel->setProperty("status", "info");
    statusLabel->setAlignment(Qt::AlignCenter);
    statusLabel->setMinimumHeight(40);

    // Компоновка всех элементов
    mainLayout->addLayout(topPanelLayout);
    mainLayout->addWidget(parametersGroup);
    mainLayout->addWidget(inputOutputContainer);
    mainLayout->addWidget(consoleGroup);
    mainLayout->addStretch(1);
    mainLayout->addWidget(statusLabel);

    // Подключение сигналов
    connect(m_cipherComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onCipherChanged);
    connect(encryptButton, &QPushButton::clicked,
            this, &MainWindow::onEncryptClicked);
    connect(decryptButton, &QPushButton::clicked,
            this, &MainWindow::onDecryptClicked);
    connect(m_advancedSettingsButton, &QPushButton::clicked,
            this, &MainWindow::onAdvancedSettingsClicked);

    // CLEAR
    connect(clearButton, &QPushButton::clicked,
            this, &MainWindow::onClearClicked);
    connect(clearInputButton, &QPushButton::clicked,
            this, &MainWindow::onClearInputClicked);
    connect(clearOutputButton, &QPushButton::clicked,
            this, &MainWindow::onClearOutputClicked);
    connect(clearLogButton, &QPushButton::clicked,
            this, &MainWindow::onClearLogClicked);
    connect(swapButton, &QPushButton::clicked,
            this, &MainWindow::onSwapClicked);

    // LOG WINDOW
    connect(showLogButton, &QPushButton::clicked, this, &MainWindow::onShowLogClicked);

    // DEFAULT TEXT
    connect(defaultTextButton, &QPushButton::clicked,
            this, &MainWindow::onDefaultTextClicked);

    connect(inputTextEdit, &QTextEdit::textChanged, this, &MainWindow::onInputTextChanged);
}


void MainWindow::setupThemeSelector()
{
    // Уже настроено в setupUI()
}

void MainWindow::onThemeChanged()
{
    int themeIndex = themeComboBox->currentIndex();
    StyleManager::StyleTheme theme = static_cast<StyleManager::StyleTheme>(themeIndex);
    StyleManager::applyTheme(this, theme);

    QString themeName = themeComboBox->currentText();
    logToConsole("✓ Тема изменена: " + themeName);
}

void MainWindow::showSuccessAnimation()
{
    // Простая анимация успеха - мигание цвета
    QPropertyAnimation* animation = new QPropertyAnimation(statusLabel, "styleSheet");
    animation->setDuration(600);
    animation->setStartValue("");
    animation->setKeyValueAt(0.3, "QLabel { background-color: rgba(0, 200, 150, 0.3); }");
    animation->setKeyValueAt(0.6, "QLabel { background-color: rgba(0, 200, 150, 0.6); }");
    animation->setEndValue("");
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

void MainWindow::showErrorAnimation()
{
    // Простая анимация ошибки - красное мигание
    QPropertyAnimation* animation = new QPropertyAnimation(statusLabel, "styleSheet");
    animation->setDuration(600);
    animation->setStartValue("");
    animation->setKeyValueAt(0.3, "QLabel { background-color: rgba(255, 75, 75, 0.3); }");
    animation->setKeyValueAt(0.6, "QLabel { background-color: rgba(255, 75, 75, 0.6); }");
    animation->setEndValue("");
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

void MainWindow::setupCiphers()
{
    // Получаем список шифров из фабрики
    m_cipherComboBox->clear();
    m_cipherComboBox->addItems(CipherFactory::instance().displayNames());

    // Выбираем первый шифр
    if (m_cipherComboBox->count() > 0) {
        onCipherChanged(0);
    } else {
        logToConsole("ПРЕДУПРЕЖДЕНИЕ: Нет зарегистрированных шифров");
        statusLabel->setText("Нет доступных шифров!");
    }
}

void MainWindow::onCipherChanged(int index)
{
    Q_UNUSED(index);

    QString displayName = m_cipherComboBox->currentText();
    int cipherId = CipherFactory::instance().idFromDisplayName(displayName);

    if (cipherId == -1) {
        logToConsole("ОШИБКА: Шифр не найден: " + displayName);
        return;
    }

    // Сохраняем ID как число (исправлено: больше не QString)
    m_currentCipherId = cipherId;  // ← теперь это int, а не QString
    m_currentCipher = CipherFactory::instance().createCipher(cipherId);

    if (!m_currentCipher) {
        logToConsole("ОШИБКА: Не удалось создать шифр: " + displayName);
        statusLabel->setText("Ошибка создания шифра: " + displayName);
        return;
    }

    // Очищаем параметры
    clearParameters();

    // Получаем указатель на header layout (первый элемент в parametersLayout)
    if (parametersLayout && parametersLayout->count() > 0) {
        QLayoutItem* headerItem = parametersLayout->itemAt(0);
        if (headerItem && headerItem->layout()) {
            QHBoxLayout* headerLayout = qobject_cast<QHBoxLayout*>(headerItem->layout());

            if (headerLayout) {
                // Удаляем старое описание, если оно есть (индекс 0, перед stretch)
                if (headerLayout->count() > 1) {
                    QLayoutItem* oldDescItem = headerLayout->takeAt(0);
                    if (oldDescItem && oldDescItem->widget()) {
                        oldDescItem->widget()->deleteLater();
                    }
                    delete oldDescItem;
                }

                // Создаем и добавляем новое описание слева
                QLabel* infoLabel = new QLabel(m_currentCipher->description());
                infoLabel->setObjectName("descriptionLabel");
                infoLabel->setWordWrap(true);
                infoLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
                infoLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

                headerLayout->insertWidget(0, infoLabel);
            }
        }
    }

    // Создаем виджеты для основных параметров (исправлено: передаем cipherId как число)
    CipherWidgetFactory::instance().createMainWidgets(
        cipherId,  // ← преобразуем int в QString для совместимости с CipherWidgetFactory
        parametersGroup,
        parametersLayout,
        m_paramWidgets
    );

    // Обновляем видимость кнопки расширенных настроек
    updateAdvancedSettingsButton();

    m_currentPreviewText = inputTextEdit->toPlainText();
    if (cipherId == 29) {  // ID для route (20)
        m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    } else {
        m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    }

    logToConsole(">>> Выбран шифр: " + displayName);
    statusLabel->setText("Выбран: " + displayName + " - готов к работе");
}



void MainWindow::updateAdvancedSettingsButton()
{
    // ← ИСПРАВЛЕНО: передаем m_currentCipherId (int)
    bool hasAdvanced = CipherWidgetFactory::instance().hasAdvancedWidgets(m_currentCipherId);
    m_advancedSettingsButton->setVisible(hasAdvanced);
}


void MainWindow::onAdvancedSettingsClicked()
{
    if (m_currentCipherId == -1 || !m_currentCipher) {
        return;
    }

    QString displayName = m_cipherComboBox->currentText();
    qDebug() << "=== Opening Advanced Settings for" << displayName << "===";

    // ← ИСПРАВЛЕНО: передаем m_currentCipherId (int), а не строку
    AdvancedSettingsDialog dialog(m_currentCipherId, displayName, this);

    if (m_cipherAdvancedSettings.contains(QString::number(m_currentCipherId))) {
        dialog.setSettings(m_cipherAdvancedSettings[QString::number(m_currentCipherId)]);
    }

    QString rawText = inputTextEdit->toPlainText();
    QString filteredText = CipherUtils::filterAlphabetOnly(rawText, m_alphabet);
    dialog.setPreviewText(filteredText);

    int result = dialog.exec();
    qDebug() << "  Dialog exec returned:" << result;

    if (result == QDialog::Accepted) {
        QVariantMap advancedSettings = dialog.getSettings();
        m_cipherAdvancedSettings[QString::number(m_currentCipherId)] = advancedSettings;
        logToConsole("✓ Сохранены расширенные настройки для " + displayName);

        if (m_currentCipherId == 29) {  // ID для route
            RouteCipherAdvancedWidget* widget = dialog.getRouteAdvancedWidget();
            if (widget) {
                widget->setPreviewText(inputTextEdit->toPlainText());
            }
        }
    }
}

void MainWindow::createCipherWidgets(int cipherId)
{

    CipherWidgetFactory::instance().createMainWidgets(
        cipherId,
        parametersGroup,
        parametersLayout,
        m_paramWidgets
    );
}

QVariantMap MainWindow::collectParameters() const
{
    QVariantMap params = CipherWidgetFactory::collectValues(m_paramWidgets);

    QString currentCipherIdStr = QString::number(m_currentCipherId);
    if (m_cipherAdvancedSettings.contains(currentCipherIdStr)) {
        const QVariantMap& advancedParams = m_cipherAdvancedSettings[currentCipherIdStr];
        for (auto it = advancedParams.constBegin(); it != advancedParams.constEnd(); ++it) {
            params[it.key()] = it.value();
            qDebug() << "  Added advanced param:" << it.key() << "=" << it.value().toString();
        }
    }

    return params;
}

void MainWindow::onEncryptClicked()
{
    if (!m_currentCipher) {
        handleError("Шифр не выбран!");
        return;
    }

    QString inputText = inputTextEdit->toPlainText().trimmed();
    if (inputText.isEmpty()) {
        handleError("Введите текст для шифрования!");
        return;
    }

    setStatusText("Выполняется шифрование...", "info");

    try {
        logToConsole("\n════════════════════════════════════════");
        logToConsole("ШИФРОВАНИЕ: " + m_currentCipher->name());
        logToConsole("Входной текст: " + inputText);

        // Собираем параметры из UI
        QVariantMap params = collectParameters();

        // Логируем параметры
        for (auto it = params.constBegin(); it != params.constEnd(); ++it) {
            logToConsole(it.key() + ": " + it.value().toString());
        }

        // Выполняем шифрование с параметрами
        CipherResult result = m_currentCipher->encrypt(inputText, params);

        // Безопасная проверка результата
        QString resultText = result.result;
        QString cipherName = result.cipherName;

        // Проверяем результат на наличие ошибки
        bool hasError = resultText.isEmpty() ||
                       resultText.contains("ошибка", Qt::CaseInsensitive) ||
                       resultText.contains("error", Qt::CaseInsensitive) ||
                       cipherName.contains("ошибка", Qt::CaseInsensitive);

        if (hasError) {
            // Формируем сообщение об ошибке
            QString errorMsg;
            outputTextEdit->clear();
            if (resultText.isEmpty()) {
                errorMsg = "Пустой результат шифрования";
            } else if (resultText.length() > 100) {
                errorMsg = resultText.left(100) + "...";
            } else {
                errorMsg = resultText;
            }

            handleError(errorMsg);

            // Безопасно логируем шаги, если они есть
            if (!result.steps.isEmpty()) {
                try {
                    QString formatted = StepFormatter::formatResult(result, true, 5, " ");
                    logToConsole(formatted);
                } catch (...) {
                    logToConsole("Ошибка при форматировании шагов");
                }
            }
            return;
        }

        // Успешное шифрование
        outputTextEdit->setText(resultText);
        showSuccessAnimation();

        // Форматируем и выводим результат
        try {
            if (!result.steps.isEmpty()) {
                QString formatted = StepFormatter::formatResult(result, true, 5, " ");
                logToConsole(formatted);
            } else {
                QString formatted = StepFormatter::formatResultOnly(result, 5, " ");
                logToConsole(formatted);
            }
        } catch (...) {
            logToConsole("Результат: " + resultText);
        }

        handleSuccess("Шифрование успешно завершено! Получено символов: " +
                     QString::number(resultText.length()));

    } catch (const std::exception& e) {
        handleError(QString("Исключение: ") + e.what());
    } catch (...) {
        handleError("Неизвестное исключение при шифровании");
    }
}

void MainWindow::onDecryptClicked()
{
    if (!m_currentCipher) {
        handleError("Шифр не выбран!");
        return;
    }

    QString inputText = inputTextEdit->toPlainText().trimmed();
    if (inputText.isEmpty()) {
        handleError("Введите текст для дешифрования!");
        return;
    }

    setStatusText("Выполняется дешифрование...", "info");

    try {
        logToConsole("\n════════════════════════════════════════");
        logToConsole("ДЕШИФРОВАНИЕ: " + m_currentCipher->name());
        logToConsole("Входной текст: " + inputText);

        // Собираем параметры из UI
        QVariantMap params = collectParameters();

        // Выполняем дешифрование
        CipherResult result = m_currentCipher->decrypt(inputText, params);

        // Безопасная проверка результата
        QString resultText = result.result;
        QString cipherName = result.cipherName;

        // Проверяем результат на наличие ошибки
        bool hasError = resultText.isEmpty() ||
                       resultText.contains("ошибка", Qt::CaseInsensitive) ||
                       resultText.contains("error", Qt::CaseInsensitive) ||
                       cipherName.contains("ошибка", Qt::CaseInsensitive);

        if (hasError) {
            // Формируем сообщение об ошибке
            outputTextEdit->clear();
            QString errorMsg;
            if (resultText.isEmpty()) {
                errorMsg = "Пустой результат дешифрования";
            } else if (resultText.length() > 100) {
                errorMsg = resultText.left(100) + "...";
            } else {
                errorMsg = resultText;
            }

            handleError(errorMsg);

            // Безопасно логируем шаги, если они есть
            if (!result.steps.isEmpty()) {
                try {
                    QString formatted = StepFormatter::formatResult(result, true, 5, " ");
                    logToConsole(formatted);
                } catch (...) {
                    logToConsole("Ошибка при форматировании шагов");
                }
            }
            return;
        }

        // Успешное дешифрование
        outputTextEdit->setText(resultText);
        showSuccessAnimation();

        // Форматируем и выводим результат
        try {
            if (!result.steps.isEmpty()) {
                QString formatted = StepFormatter::formatResult(result, true, 5, " ");
                logToConsole(formatted);
            } else {
                QString formatted = StepFormatter::formatResultOnly(result, 5, " ");
                logToConsole(formatted);
            }
        } catch (...) {
            logToConsole("Результат: " + resultText);
        }

        handleSuccess("Дешифрование успешно завершено! Получено символов: " +
                     QString::number(resultText.length()));

    } catch (const std::exception& e) {
        handleError(QString("Исключение: ") + e.what());
    } catch (...) {
        handleError("Неизвестное исключение при дешифровании");
    }
}

void MainWindow::onClearClicked()
{
    inputTextEdit->clear();
    outputTextEdit->clear();
    debugConsole->clear();
    statusLabel->setText("Все поля очищены. Выберите шифр.");
    statusLabel->setStyleSheet("padding: 8px; background-color: #e8e8e8; border: 1px solid #ccc; border-radius: 3px; color: black;");
    logToConsole("=== Все поля очищены ===");
}


void MainWindow::clearParameters()
{
    // Очищаем хранилище указателей
    m_paramWidgets.clear();

    // Удаляем ВСЕ дочерние виджеты, КРОМЕ:
    // 1. Самого parametersGroup
    // 2. Кнопки расширенных настроек
    // 3. Заголовка (если мы его где-то сохранили)

    QList<QWidget*> widgets = parametersGroup->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
    for (QWidget* widget : widgets) {
        // НЕ УДАЛЯЕМ кнопку расширенных настроек!
        if (widget != parametersGroup &&
            widget != m_advancedSettingsButton) {

            // Проверяем, не является ли виджет частью заголовка
            bool isHeaderWidget = false;
            if (parametersLayout && parametersLayout->count() > 0) {
                QLayoutItem* firstItem = parametersLayout->itemAt(0);
                if (firstItem && firstItem->layout()) {
                    QLayout* headerLayout = firstItem->layout();
                    // Проверяем, принадлежит ли widget этому layout'у
                    if (headerLayout->indexOf(widget) != -1) {
                        isHeaderWidget = true;
                    }
                }
            }

            // Удаляем только если это не виджет из заголовка
            if (!isHeaderWidget) {
                widget->hide();
                widget->deleteLater();
            }
        }
    }

    // Удаляем все layout-элементы, КРОМЕ первого (заголовка)
    while (parametersLayout && parametersLayout->count() > 1) {
        QLayoutItem* item = parametersLayout->takeAt(1);
        if (item) {
            if (item->layout()) {
                // Рекурсивно очищаем layout
                QLayout* subLayout = item->layout();
                QLayoutItem* child;
                while ((child = subLayout->takeAt(0))) {
                    delete child;
                }
            }
            if (item->widget()) {
                item->widget()->deleteLater();
            }
            delete item;
        }
    }
}

void MainWindow::logToConsole(const QString& message)
{
    debugConsole->append(message);
    // Автоскроллинг к низу
    QTextCursor cursor = debugConsole->textCursor();
    cursor.movePosition(QTextCursor::End);
    debugConsole->setTextCursor(cursor);

    std::cout << message.toStdString() << std::endl;
}

void MainWindow::onClearInputClicked()
{
    inputTextEdit->clear();
    logToConsole("✓ Поле ввода очищено");
}

void MainWindow::onClearOutputClicked()
{
    outputTextEdit->clear();
    logToConsole("✓ Поле вывода очищено");
}

void MainWindow::onClearLogClicked()
{
    debugConsole->clear();
    logToConsole("✓ Журнал операций очищен");
}

void MainWindow::onSwapClicked()
{
    QString inputText = inputTextEdit->toPlainText();
    QString outputText = outputTextEdit->toPlainText();

    inputTextEdit->setPlainText(outputText);
    outputTextEdit->setPlainText(inputText);

    logToConsole("✓ Входной и выходной текст поменяны местами");
}

void MainWindow::onDefaultTextClicked()
{
    QString defaultText = "ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК";
    inputTextEdit->setPlainText(defaultText);
    logToConsole("✓ Вставлен пример текста: \"" + defaultText + "\"");
}


void MainWindow::onShowLogClicked()
{
    // Передаем текущий лог в окно
    logWindow->setLogContent(debugConsole->toPlainText());
    logWindow->show();
    logWindow->raise();
    logWindow->activateWindow();

    logToConsole("✓ Открыт детальный журнал операций");
}

void MainWindow::setStatusText(const QString& text, const QString& type)
{
    if (!statusLabel) return;

    statusLabel->setText(text);
    statusLabel->setProperty("status", type);

    // Принудительно обновляем стиль
    statusLabel->style()->unpolish(statusLabel);
    statusLabel->style()->polish(statusLabel);

    // Сбрасываем таймер, если он уже запущен
    if (m_statusResetTimer) {
        m_statusResetTimer->stop();
    } else {
        m_statusResetTimer = new QTimer(this);
        m_statusResetTimer->setSingleShot(true);
        connect(m_statusResetTimer, &QTimer::timeout, [this]() {
            if (statusLabel) {
                statusLabel->setText("⚡ Готов к работе");
                statusLabel->setProperty("status", "info");
                statusLabel->style()->unpolish(statusLabel);
                statusLabel->style()->polish(statusLabel);
            }
        });
    }

    // Сбрасываем через 5 секунд
    m_statusResetTimer->start(5000);
}

void MainWindow::flashWindow(const QColor& color, int duration)
{
    // Создаем полупрозрачный colored overlay
    QFrame* overlay = new QFrame(this);
    overlay->setGeometry(rect());
    overlay->setStyleSheet(QString(
        "background-color: rgba(%1, %2, %3, 0.15);"
        "border: 4px solid rgba(%1, %2, %3, 0.8);"
    ).arg(color.red()).arg(color.green()).arg(color.blue()));

    overlay->raise();
    overlay->show();

    // Просто удаляем через duration
    QTimer::singleShot(duration, [overlay]() {
        overlay->deleteLater();
    });
}

void MainWindow::handleError(const QString& errorMessage)
{
    if (!statusLabel) return;

    setStatusText("❌ " + errorMessage, "error");

    // Безопасная вспышка окна
    try {
        flashWindow(QColor(255, 75, 75), 800);
    } catch (...) {
        // Игнорируем ошибки анимации
    }

    logToConsole("❌ ОШИБКА: " + errorMessage);
}

void MainWindow::handleSuccess(const QString& successMessage)
{
    setStatusText("✅ " + successMessage, "success");
    logToConsole("✅ " + successMessage);
}


void MainWindow::onInputTextChanged()
{
}


void MainWindow::onFilterButtonClicked()
{
    if (!m_filterDialog) {
        m_filterDialog = new CategoryFilterDialog(this);
    }

    // Устанавливаем текущие выбранные категории
    m_filterDialog->setSelectedCategories(m_activeCategories);

    // Показываем диалог
    if (m_filterDialog->exec() == QDialog::Accepted) {
        applyFilter();
    }
}

void MainWindow::applyFilter()
{
    if (!m_filterDialog) return;

    // Получаем выбранные категории
    m_activeCategories = m_filterDialog->selectedCategories();

    // Обновляем список шифров
    QStringList cipherNames;

    if (m_activeCategories.isEmpty()) {
        // Если ничего не выбрано, показываем все
        cipherNames = CipherFactory::instance().displayNames();
    } else {
        cipherNames = CipherFactory::instance().displayNames(m_activeCategories);
    }

    // Сохраняем текущее выбранное имя
    QString currentName = m_cipherComboBox->currentText();

    // Обновляем комбобокс
    m_cipherComboBox->blockSignals(true);
    m_cipherComboBox->clear();
    m_cipherComboBox->addItems(cipherNames);

    // Восстанавливаем выбор
    int index = m_cipherComboBox->findText(currentName);
    if (index >= 0) {
        m_cipherComboBox->setCurrentIndex(index);
    } else if (m_cipherComboBox->count() > 0) {
        m_cipherComboBox->setCurrentIndex(0);
    }
    m_cipherComboBox->blockSignals(false);

    // ВАЖНО: Принудительно вызываем onCipherChanged для первого элемента
    if (m_cipherComboBox->count() > 0) {
        onCipherChanged(m_cipherComboBox->currentIndex());
    }

    // Логируем результат
    logToConsole(QString("Фильтр обновлен: показано %1 из %2 шифров")
                 .arg(cipherNames.size())
                 .arg(CipherFactory::instance().displayNames().size()));
}

void MainWindow::onAnalysisWindowOpen()
{
    if (!m_analysisWindow) {
        m_analysisWindow = new AnalysisWindow(this);
        m_analysisWindow->setAttribute(Qt::WA_DeleteOnClose);
        connect(m_analysisWindow, &QDialog::destroyed, [this]() {
            m_analysisWindow = nullptr;
        });
    }

    m_analysisWindow->setTexts(inputTextEdit->toPlainText(), outputTextEdit->toPlainText());
    m_analysisWindow->show();
    m_analysisWindow->raise();
    m_analysisWindow->activateWindow();
}

void MainWindow::onLibraryWindowOpen()
{
    if (!m_libraryWindow) {
        m_libraryWindow = new LibraryWindow(this);
        m_libraryWindow->setAttribute(Qt::WA_DeleteOnClose);
        connect(m_libraryWindow, &QDialog::destroyed, [this]() {
            m_libraryWindow = nullptr;
        });
    }

    m_libraryWindow->show();
    m_libraryWindow->raise();
    m_libraryWindow->activateWindow();
}
