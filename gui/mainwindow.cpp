#include "mainwindow.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "formatter.h"
#include "stylemanager.h"

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
#include <QLineEdit>
#include <QPropertyAnimation>
#include <QGraphicsDropShadowEffect>
#include <QSequentialAnimationGroup>
#include <QParallelAnimationGroup>

// ==================== AnimatedButton Implementation ====================
AnimatedButton::AnimatedButton(const QString& text, QWidget* parent)
    : QPushButton(text, parent)
{
    setCursor(Qt::PointingHandCursor);

    m_hoverAnimation = new QPropertyAnimation(this, "borderRadius");
    m_hoverAnimation->setDuration(150);
    m_hoverAnimation->setEasingCurve(QEasingCurve::OutCubic);
}

AnimatedButton::~AnimatedButton() {
    delete m_hoverAnimation;
}

void AnimatedButton::setBorderRadius(int radius) {
    m_borderRadius = radius;
    QString style = QString(
        "QPushButton {"
        "    border-radius: %1px;"
        "}"
    ).arg(radius);
    setStyleSheet(style);
}

void AnimatedButton::enterEvent(QEnterEvent* event) {
    QPushButton::enterEvent(event);
    m_hoverAnimation->stop();
    m_hoverAnimation->setStartValue(borderRadius());
    m_hoverAnimation->setEndValue(10);
    m_hoverAnimation->start();
}

void AnimatedButton::leaveEvent(QEvent* event) {
    QPushButton::leaveEvent(event);
    m_hoverAnimation->stop();
    m_hoverAnimation->setStartValue(borderRadius());
    m_hoverAnimation->setEndValue(6);
    m_hoverAnimation->start();
}



// ==================== MainWindow Implementation ====================
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , cipherComboBox(nullptr)
    , themeComboBox(nullptr)
    , inputTextEdit(nullptr)
    , outputTextEdit(nullptr)
    , debugConsole(nullptr)
    , encryptButton(nullptr)
    , decryptButton(nullptr)
    , clearButton(nullptr)
    , statusLabel(nullptr)
    , parametersGroup(nullptr)
    , parametersLayout(nullptr)
{
    setupUI();
    setupCiphers();
    setupThemeSelector();

    // Применяем тему по умолчанию
    StyleManager::applyTheme(this, StyleManager::THEME_CYBER_MIDNIGHT);

    setWindowTitle("CryptoGuard - Криптографическое приложение");
    resize(900, 700);

    logToConsole("=== CryptoGuard запущен ===");
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
    QLabel *logoLabel = new QLabel("🔒 CryptoGuard");
    logoLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: #00c896;");
    topPanelLayout->addWidget(logoLabel);
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
    cipherComboBox = new QComboBox();
    cipherComboBox->setMinimumWidth(220);
    cipherComboBox->setObjectName("cipherSelector");

    topPanelLayout->addWidget(cipherLabel);
    topPanelLayout->addWidget(cipherComboBox);

    // 2. Панель параметров (с эффектом стекла)

    parametersGroup = new QGroupBox("Параметры шифра");
    parametersLayout = new QVBoxLayout(parametersGroup);
    parametersGroup->setLayout(parametersLayout);

    // Эффект стекла
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
    buttonLayout->addStretch(); // Растягиваем пространство снизу

    // Создаем горизонтальный контейнер для ввода, кнопок и вывода
    QWidget *inputOutputContainer = new QWidget();
    QHBoxLayout *horizontalLayout = new QHBoxLayout(inputOutputContainer);
    horizontalLayout->setSpacing(15);
    horizontalLayout->setContentsMargins(0, 0, 0, 0);

    // Добавляем ввод, кнопки и вывод в горизонтальный layout
    horizontalLayout->addWidget(inputGroup, 1);  // Растягиваем по ширине
    horizontalLayout->addWidget(buttonContainer, 0);  // Фиксированная ширина для кнопок
    horizontalLayout->addWidget(outputGroup, 1);  // Растягиваем по ширине

    // 6. Консоль для логов
    QGroupBox *consoleGroup = new QGroupBox("📋 Журнал операций");
    QVBoxLayout *consoleLayout = new QVBoxLayout(consoleGroup);
    consoleLayout->setSpacing(5);
    consoleLayout->setContentsMargins(5, 5, 5, 5);

    debugConsole = new QTextEdit();
    debugConsole->setReadOnly(true);
    debugConsole->setObjectName("console");
    debugConsole->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    // Кнопка очистки лога

    QHBoxLayout *consoleToolsLayout = new QHBoxLayout();
    clearLogButton = new QPushButton("🗑️ Очистить лог");
    clearLogButton->setObjectName("clearLogButton");
    clearLogButton->setToolTip("Очистить журнал операций");
    clearLogButton->setMaximumWidth(120);
    consoleToolsLayout->addStretch();
    consoleToolsLayout->addWidget(clearLogButton);

    consoleLayout->addWidget(debugConsole);
    consoleLayout->addLayout(consoleToolsLayout);
    consoleGroup->setLayout(consoleLayout);

    // 7. Статусная панель
    statusLabel = new QLabel("⚡ Готов к работе. Выберите шифр из списка.");
    statusLabel->setProperty("status", "info");
    statusLabel->setAlignment(Qt::AlignCenter);
    statusLabel->setMinimumHeight(40);

    // Компоновка всех элементов
    mainLayout->addLayout(topPanelLayout);
    mainLayout->addWidget(parametersGroup);
    mainLayout->addWidget(inputOutputContainer);  // Вместо отдельных inputGroup, buttonContainer, outputGroup
    mainLayout->addWidget(consoleGroup);
    mainLayout->addStretch(1);
    mainLayout->addWidget(statusLabel);


    // Подключение сигналов
    connect(cipherComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onCipherChanged);
    connect(encryptButton, &QPushButton::clicked,
            this, &MainWindow::onEncryptClicked);
    connect(decryptButton, &QPushButton::clicked,
            this, &MainWindow::onDecryptClicked);

    //CLEAR
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
    //CLEAR

    // DEFAULT TEXT
    connect(defaultTextButton, &QPushButton::clicked,
            this, &MainWindow::onDefaultTextClicked);
    //
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
    cipherComboBox->clear();
    cipherComboBox->addItems(CipherFactory::instance().displayNames());

    // Выбираем первый шифр
    if (cipherComboBox->count() > 0) {
        onCipherChanged(0);
    } else {
        logToConsole("ПРЕДУПРЕЖДЕНИЕ: Нет зарегистрированных шифров");
        statusLabel->setText("Нет доступных шифров!");
    }
}

void MainWindow::onCipherChanged(int index)
{
    Q_UNUSED(index);

    QString displayName = cipherComboBox->currentText();
    QString cipherId = CipherFactory::instance().idFromDisplayName(displayName);

    if (cipherId.isEmpty()) {
        logToConsole("ОШИБКА: Шифр не найден: " + displayName);
        return;
    }

    m_currentCipher = CipherFactory::instance().createCipher(cipherId);

    if (!m_currentCipher) {
        logToConsole("ОШИБКА: Не удалось создать шифр: " + displayName);
        statusLabel->setText("Ошибка создания шифра: " + displayName);
        return;
    }

    // Очищаем параметры
    clearParameters();

    // Добавляем описание шифра
    QLabel* infoLabel = new QLabel(m_currentCipher->description());
    infoLabel->setObjectName("descriptionLabel");
    infoLabel->setWordWrap(true);
    parametersLayout->addWidget(infoLabel);

    // Создаем виджеты для параметров через фабрику
    createCipherWidgets(cipherId);

    logToConsole(">>> Выбран шифр: " + displayName);
    statusLabel->setText("Выбран: " + displayName + " - готов к работе");
}

void MainWindow::createCipherWidgets(const QString& cipherId)
{
    // Вся логика создания виджетов теперь в фабрике
    CipherWidgetFactory::instance().createWidgets(
        cipherId,
        parametersGroup,
        parametersLayout,
        m_paramWidgets
    );
}

QVariantMap MainWindow::collectParameters() const
{
    // Используем статический метод фабрики
    return CipherWidgetFactory::collectValues(m_paramWidgets);
}


void MainWindow::onEncryptClicked()
{
    if (!m_currentCipher) {
        QMessageBox::warning(this, "Ошибка", "Шифр не выбран!");
        return;
    }

    QString inputText = inputTextEdit->toPlainText().trimmed();
    if (inputText.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для шифрования!");
        return;
    }

    statusLabel->setText("Выполняется шифрование...");
    statusLabel->setStyleSheet("padding: 8px; background-color: #ffffcc; border: 1px solid #ffcc00; border-radius: 3px; color: black;");

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

        // Выводим результат
        outputTextEdit->setText(result.result);
        showSuccessAnimation();
        statusLabel->setText("✓ Шифрование завершено!");
        statusLabel->setProperty("status", "success");
        // === ДОБАВЛЕНО: Используем StepFormatter для красивого вывода ===
        if (!result.steps.isEmpty()) {
            // Выводим детализированный результат с шагами
            QString formatted = StepFormatter::formatResult(result, true, 5, " ");
            logToConsole(formatted);
        } else {
            // Если нет шагов, выводим просто результат
            QString formatted = StepFormatter::formatResultOnly(result, 5, " ");
            logToConsole(formatted);
        }

        statusLabel->setText("Шифрование завершено! Символов: " + QString::number(result.steps.size()));
        statusLabel->setStyleSheet("padding: 8px; background-color: #ccffcc; border: 1px solid #00cc00; border-radius: 3px; color: black;");

    } catch (const std::exception& e) {
        showErrorAnimation();
        statusLabel->setText("✗ Ошибка при шифровании!");
        statusLabel->setProperty("status", "error");
    }
}

void MainWindow::onDecryptClicked()
{
    if (!m_currentCipher) {
        QMessageBox::warning(this, "Ошибка", "Шифр не выбран!");
        return;
    }

    QString inputText = inputTextEdit->toPlainText().trimmed();
    if (inputText.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для дешифрования!");
        return;
    }

    statusLabel->setText("Выполняется дешифрование...");
    statusLabel->setStyleSheet("padding: 8px; background-color: #ffffcc; border: 1px solid #ffcc00; border-radius: 3px; color: black;");

    try {
        logToConsole("\n════════════════════════════════════════");
        logToConsole("ДЕШИФРОВАНИЕ: " + m_currentCipher->name());
        logToConsole("Входной текст: " + inputText);

        // Собираем параметры из UI
        QVariantMap params = collectParameters();

        // Выполняем дешифрование
        CipherResult result = m_currentCipher->decrypt(inputText, params);

        // Выводим результат
        outputTextEdit->setText(result.result);
        showSuccessAnimation();
        statusLabel->setText("✓ Шифрование завершено!");
        statusLabel->setProperty("status", "success");
        // === ДОБАВЛЕНО: Используем StepFormatter для красивого вывода ===
        if (!result.steps.isEmpty()) {
            QString formatted = StepFormatter::formatResult(result, true, 5, " ");
            logToConsole(formatted);
        } else {
            QString formatted = StepFormatter::formatResultOnly(result, 5, " ");
            logToConsole(formatted);
        }

        statusLabel->setText("Дешифрование завершено!");
        statusLabel->setStyleSheet("padding: 8px; background-color: #ccffcc; border: 1px solid #00cc00; border-radius: 3px; color: black;");

    } catch (const std::exception& e) {
        showErrorAnimation();
        statusLabel->setText("✗ Ошибка при шифровании!");
        statusLabel->setProperty("status", "error");
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
    // Очищаем хранилище указателей (без удаления виджетов!)
    m_paramWidgets.clear();

    // Находим все виджеты в parametersGroup и удаляем их
    QList<QWidget*> widgets = parametersGroup->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
    for (QWidget* widget : widgets) {
        // Исключаем сам parametersGroup из списка
        if (widget != parametersGroup) {
            widget->hide();
            widget->deleteLater();
        }
    }

    // Пересоздаем чистый layout
    delete parametersLayout;
    parametersLayout = new QVBoxLayout(parametersGroup);
    parametersGroup->setLayout(parametersLayout);
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
