#include "mainwindow.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "formatter.h"

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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , cipherComboBox(nullptr)
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

    setWindowTitle("Криптографическое приложение с фабрикой");
    resize(800, 600);

    logToConsole("=== Приложение запущено ===");
    logToConsole("Фабрика шифров инициализирована");
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUI()
{
    // Центральный виджет
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Основной layout
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // 1. Выбор шифра
    QHBoxLayout *cipherSelectionLayout = new QHBoxLayout();
    cipherSelectionLayout->addWidget(new QLabel("Выберите шифр:"));
    cipherComboBox = new QComboBox();
    cipherComboBox->setMinimumWidth(250);


    // Устанавливаем фиксированную высоту выпадающего списка
    cipherComboBox->setStyleSheet(
        "QComboBox {"
        "    combobox-popup: 0;"  // Отключаем авто-высоту
        "}"
        "QComboBox QAbstractItemView {"
        "    max-height: 200px;"  // Фиксированная высота
        "}"
    );

    cipherSelectionLayout->addWidget(cipherComboBox);

    // 2. Панель параметров
    parametersGroup = new QGroupBox("Параметры шифра");
    parametersLayout = new QVBoxLayout(parametersGroup);
    parametersGroup->setLayout(parametersLayout);

    // 3. Ввод текста
    QGroupBox *inputGroup = new QGroupBox("Входной текст");
    QVBoxLayout *inputLayout = new QVBoxLayout();
    inputTextEdit = new QTextEdit();
    inputTextEdit->setText("ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК");
    inputTextEdit->setPlaceholderText("Введите текст для шифрования/дешифрования...");
    inputTextEdit->setMaximumHeight(100);
    inputLayout->addWidget(inputTextEdit);
    inputGroup->setLayout(inputLayout);

    // 4. Кнопки
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    encryptButton = new QPushButton("Зашифровать");
    decryptButton = new QPushButton("Расшифровать");
    clearButton = new QPushButton("Очистить всё");
    buttonLayout->addWidget(encryptButton);
    buttonLayout->addWidget(decryptButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(clearButton);

    // 5. Вывод результата
    QGroupBox *outputGroup = new QGroupBox("Результат");
    QVBoxLayout *outputLayout = new QVBoxLayout();
    outputTextEdit = new QTextEdit();
    outputTextEdit->setReadOnly(true);
    outputTextEdit->setPlaceholderText("Здесь появится результат...");
    outputTextEdit->setMaximumHeight(100);
    outputLayout->addWidget(outputTextEdit);
    outputGroup->setLayout(outputLayout);

    // 6. Консоль для логов
    QGroupBox *consoleGroup = new QGroupBox("Лог выполнения");
    QVBoxLayout *consoleLayout = new QVBoxLayout();
    debugConsole = new QTextEdit();
    debugConsole->setReadOnly(true);
    debugConsole->setMaximumHeight(150);
    debugConsole->setStyleSheet("font-family: 'Courier New', monospace; font-size: 10pt; background-color: #f8f8f8; color: #000000;");
    consoleLayout->addWidget(debugConsole);
    consoleGroup->setLayout(consoleLayout);

    // 7. Статус
    statusLabel = new QLabel("Готов к работе. Выберите шифр из списка.");
    statusLabel->setStyleSheet("padding: 8px; background-color: #e8e8e8; border: 1px solid #ccc; border-radius: 3px; color: black;");
    statusLabel->setAlignment(Qt::AlignCenter);

    // Компоновка
    mainLayout->addLayout(cipherSelectionLayout);
    mainLayout->addWidget(parametersGroup);
    mainLayout->addWidget(inputGroup);
    mainLayout->addLayout(buttonLayout);
    mainLayout->addWidget(outputGroup);
    mainLayout->addWidget(consoleGroup);
    mainLayout->addWidget(statusLabel);

    // Подключение сигналов
    connect(cipherComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onCipherChanged);
    connect(encryptButton, &QPushButton::clicked,
            this, &MainWindow::onEncryptClicked);
    connect(decryptButton, &QPushButton::clicked,
            this, &MainWindow::onDecryptClicked);
    connect(clearButton, &QPushButton::clicked,
            this, &MainWindow::onClearClicked);
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
        QString error = QString("Ошибка: %1").arg(e.what());
        logToConsole("ОШИБКА: " + error);
        QMessageBox::critical(this, "Ошибка", error);

        statusLabel->setText("Ошибка при шифровании!");
        statusLabel->setStyleSheet("padding: 8px; background-color: #ffcccc; border: 1px solid #ff0000; border-radius: 3px; color: black;");
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
        QString error = QString("Ошибка: %1").arg(e.what());
        logToConsole("ОШИБКА: " + error);
        QMessageBox::critical(this, "Ошибка", error);

        statusLabel->setText("Ошибка при дешифровании!");
        statusLabel->setStyleSheet("padding: 8px; background-color: #ffcccc; border: 1px solid #ff0000; border-radius: 3px; color: black;");
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
    std::cout << message.toStdString() << std::endl;
}
