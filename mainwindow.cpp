#include "mainwindow.h"
#include "atbash.h"
#include "caesar.h"
#include "vigenere_auto.h"
#include "formatter.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QComboBox>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QSpinBox>
#include <QLineEdit>
#include <QMessageBox>
#include <iostream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      cipherComboBox(nullptr),
      inputTextEdit(nullptr),
      outputTextEdit(nullptr),
      debugConsole(nullptr),
      encryptButton(nullptr),
      decryptButton(nullptr),
      clearButton(nullptr),
      statusLabel(nullptr),
      parametersGroup(nullptr),
      parametersLayout(nullptr),
      shiftSpinBox(nullptr),
      keyLineEdit(nullptr),
      startCharLineEdit(nullptr) {

    setupUI();
    setupCiphers();

    setWindowTitle("Криптографическое приложение");
    resize(800, 600);

    logToConsole("=== Приложение запущено ===");
}

MainWindow::~MainWindow() {
    // Qt автоматически удалит все виджеты
}

void MainWindow::setupUI() {
    // Центральный виджет
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Основной layout
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // 1. Выбор шифра - КОМБО-БОКС!
    QHBoxLayout *cipherSelectionLayout = new QHBoxLayout();
    cipherSelectionLayout->addWidget(new QLabel("Выберите шифр:"));
    cipherComboBox = new QComboBox();
    cipherComboBox->setMinimumWidth(200);
    cipherSelectionLayout->addWidget(cipherComboBox);
    cipherSelectionLayout->addStretch();

    // 2. Панель параметров (изначально пустая)
    parametersGroup = new QGroupBox("Параметры шифра");
    parametersLayout = new QVBoxLayout(parametersGroup);
    parametersGroup->setLayout(parametersLayout);

    // 3. Ввод текста
    QGroupBox *inputGroup = new QGroupBox("Входной текст");
    QVBoxLayout *inputLayout = new QVBoxLayout();
    inputTextEdit = new QTextEdit();
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

    // 7. Статус
    statusLabel = new QLabel("Готов к работе. Выберите шифр из списка.");
    statusLabel->setStyleSheet("padding: 8px; background-color: #e8e8e8; border: 1px solid #ccc; border-radius: 3px; color: black;");
    statusLabel->setAlignment(Qt::AlignCenter);

    // Компоновка всех элементов
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
    connect(encryptButton, &QPushButton::clicked, this, &MainWindow::onEncryptClicked);
    connect(decryptButton, &QPushButton::clicked, this, &MainWindow::onDecryptClicked);
    connect(clearButton, &QPushButton::clicked, this, &MainWindow::onClearClicked);
}

void MainWindow::setupCiphers() {
    // Заполняем ComboBox шифрами
    cipherComboBox->addItem("Атбаш");
    cipherComboBox->addItem("Шифр Цезаря");
    cipherComboBox->addItem("Виженер (самоключ)");
    cipherComboBox->addItem("Тритемий");
    cipherComboBox->addItem("Белазо");
    cipherComboBox->addItem("Матричный шифр");
    cipherComboBox->addItem("Маршрутная перестановка");
    cipherComboBox->addItem("Шифр Кардано");

    // Настраиваем шифраторы

    // 1. Атбаш
    encryptors["Атбаш"] = [](const QString& text) {
        AtbashCipher cipher;
        return cipher.encrypt(text);
    };
    decryptors["Атбаш"] = encryptors["Атбаш"]; // Atbash симметричен

    // 2. Цезарь
    encryptors["Шифр Цезаря"] = [this](const QString& text) {
        CaesarCipher cipher;
        return cipher.encrypt(text, getCaesarShift());
    };
    decryptors["Шифр Цезаря"] = [this](const QString& text) {
        CaesarCipher cipher;
        return cipher.decrypt(text, getCaesarShift());
    };

    // 3. Виженер
    encryptors["Виженер (самоключ)"] = [this](const QString& text) {
        VigenereAutoCipher cipher;
        return cipher.encrypt(text, getVigenereStartChar());
    };
    decryptors["Виженер (самоключ)"] = [this](const QString& text) {
        // Предполагаем, что шифр симметричный
        VigenereAutoCipher cipher;
        return cipher.encrypt(text, getVigenereStartChar());
    };

    // 4. Тритемий - ЗАГЛУШКА
    encryptors["Тритемий"] = [](const QString& text) {
        return CipherResult("Тритемий: введите текст");
    };
    decryptors["Тритемий"] = encryptors["Тритемий"];

    // 5. Белазо - ЗАГЛУШКА
    encryptors["Белазо"] = [](const QString& text) {
        return CipherResult("Белазо: введите текст");
    };
    decryptors["Белазо"] = encryptors["Белазо"];

    // 6. Матричный - ЗАГЛУШКА
    encryptors["Матричный шифр"] = [](const QString& text) {
        return CipherResult("Матричный: введите текст");
    };
    decryptors["Матричный шифр"] = encryptors["Матричный шифр"];

    // 7. Маршрутная - ЗАГЛУШКА
    encryptors["Маршрутная перестановка"] = [](const QString& text) {
        return CipherResult("Маршрутная: введите текст");
    };
    decryptors["Маршрутная перестановка"] = encryptors["Маршрутная перестановка"];

    // 8. Кардано - ЗАГЛУШКА
    encryptors["Шифр Кардано"] = [](const QString& text) {
        return CipherResult("Кардано: введите текст");
    };
    decryptors["Шифр Кардано"] = encryptors["Шифр Кардано"];

    // Автоматически выбираем первый шифр
    onCipherChanged();
}

void MainWindow::onCipherChanged() {
    QString cipherName = cipherComboBox->currentText();

    // Очищаем старые параметры
    clearParameters();

    // Создаем новые параметры в зависимости от выбранного шифра
    if (cipherName == "Атбаш") {
        setupAtbashParameters();
    }
    else if (cipherName == "Шифр Цезаря") {
        setupCaesarParameters();
    }
    else if (cipherName == "Виженер (самоключ)") {
        setupVigenereParameters();
    }
    else if (cipherName == "Тритемий") {
        setupTrithemiusParameters();
    }
    else if (cipherName == "Белазо") {
        setupBelazoParameters();
    }
    else if (cipherName == "Матричный шифр") {
        setupMatrixParameters();
    }
    else if (cipherName == "Маршрутная перестановка") {
        setupRouteParameters();
    }
    else if (cipherName == "Шифр Кардано") {
        setupCardanoParameters();
    }
    else {
        // Для остальных шифров - просто сообщение
        QLabel* infoLabel = new QLabel("Параметры для этого шифра пока не реализованы");
        infoLabel->setWordWrap(true);
        parametersLayout->addWidget(infoLabel);
    }

    logToConsole(">>> Выбран шифр: " + cipherName);
    statusLabel->setText("Выбран: " + cipherName + " - готов к работе");
}

void MainWindow::clearParameters() {
    // Удаляем старые виджеты параметров
    QLayoutItem* item;
    while ((item = parametersLayout->takeAt(0)) != nullptr) {
        if (item->widget()) {
            // Запоминаем указатели на динамические элементы
            QWidget* widget = item->widget();
            if (widget == shiftSpinBox) shiftSpinBox = nullptr;
            else if (widget == keyLineEdit) keyLineEdit = nullptr;
            else if (widget == startCharLineEdit) startCharLineEdit = nullptr;

            delete widget;
        }
        delete item;
    }

    // Обнуляем указатели
    shiftSpinBox = nullptr;
    keyLineEdit = nullptr;
    startCharLineEdit = nullptr;
}

void MainWindow::setupAtbashParameters() {
    QLabel* infoLabel = new QLabel("Зеркальный шифр. Каждая буква заменяется на симметричную относительно центра алфавита.");
    infoLabel->setWordWrap(true);
    parametersLayout->addWidget(infoLabel);
}

void MainWindow::setupCaesarParameters() {
    // Layout для сдвига
    QHBoxLayout* shiftLayout = new QHBoxLayout();

    QLabel* shiftLabel = new QLabel("Сдвиг:");
    shiftLabel->setMinimumWidth(60);

    shiftSpinBox = new QSpinBox();
    shiftSpinBox->setRange(1, 33);
    shiftSpinBox->setValue(3);
    shiftSpinBox->setToolTip("На сколько позиций сдвигать алфавит (1-33)");
    shiftSpinBox->setMinimumWidth(80);

    QLabel* exampleLabel = new QLabel("Пример: при сдвиге 3, А→Г, Б→Д, ...");
    exampleLabel->setStyleSheet("color: #666; font-size: 9pt;");

    shiftLayout->addWidget(shiftLabel);
    shiftLayout->addWidget(shiftSpinBox);
    shiftLayout->addStretch();
    shiftLayout->addWidget(exampleLabel);

    parametersLayout->addLayout(shiftLayout);
}

void MainWindow::setupVigenereParameters() {
    // Layout для начального символа
    QHBoxLayout* charLayout = new QHBoxLayout();

    QLabel* charLabel = new QLabel("Начальный символ:");
    charLabel->setMinimumWidth(120);

    startCharLineEdit = new QLineEdit();
    startCharLineEdit->setText("А");
    startCharLineEdit->setMaxLength(1);
    startCharLineEdit->setMaximumWidth(50);
    startCharLineEdit->setToolTip("Первый символ самоключа (обычно 'А' или 'Ю')");

    QLabel* infoLabel = new QLabel("Пример: при 'Ю' ключ начинается с 'Ю'");
    infoLabel->setStyleSheet("color: #666; font-size: 9pt;");

    charLayout->addWidget(charLabel);
    charLayout->addWidget(startCharLineEdit);
    charLayout->addStretch();
    charLayout->addWidget(infoLabel);

    parametersLayout->addLayout(charLayout);
}

// РЕАЛИЗАЦИИ НОВЫХ ФУНКЦИЙ:

void MainWindow::setupTrithemiusParameters() {
    QLabel* infoLabel = new QLabel("Линейный шифр: каждая следующая буква сдвигается на 1 больше предыдущей.");
    infoLabel->setWordWrap(true);
    parametersLayout->addWidget(infoLabel);
}

void MainWindow::setupBelazoParameters() {
    QHBoxLayout* keyLayout = new QHBoxLayout();

    QLabel* keyLabel = new QLabel("Ключ:");
    keyLabel->setMinimumWidth(60);

    keyLineEdit = new QLineEdit();
    keyLineEdit->setText("ЗОНД");
    keyLineEdit->setToolTip("Ключевое слово для шифра Белазо");

    keyLayout->addWidget(keyLabel);
    keyLayout->addWidget(keyLineEdit);
    keyLayout->addStretch();

    parametersLayout->addLayout(keyLayout);
}

void MainWindow::setupMatrixParameters() {
    QLabel* infoLabel = new QLabel("Матричный шифр: умножение текста на квадратную матрицу.");
    infoLabel->setWordWrap(true);
    parametersLayout->addWidget(infoLabel);
}

void MainWindow::setupRouteParameters() {
    QLabel* infoLabel = new QLabel("Маршрутная перестановка: запись в таблицу и чтение по маршруту.");
    infoLabel->setWordWrap(true);
    parametersLayout->addWidget(infoLabel);
}

void MainWindow::setupCardanoParameters() {
    QLabel* infoLabel = new QLabel("Шифр Кардано: использование решетки с отверстиями.");
    infoLabel->setWordWrap(true);
    parametersLayout->addWidget(infoLabel);
}

int MainWindow::getCaesarShift() const {
    return shiftSpinBox ? shiftSpinBox->value() : 3;
}

QString MainWindow::getVigenereKey() const {
    return keyLineEdit ? keyLineEdit->text() : "КЛЮЧ";
}

QChar MainWindow::getVigenereStartChar() const {
    if (startCharLineEdit && !startCharLineEdit->text().isEmpty()) {
        return startCharLineEdit->text().at(0).toUpper();
    }
    return QChar('А');
}

void MainWindow::onEncryptClicked() {
    QString cipherName = cipherComboBox->currentText();
    QString inputText = inputTextEdit->toPlainText().trimmed();

    if (inputText.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для шифрования!");
        return;
    }

    if (!encryptors.contains(cipherName)) {
        logToConsole("ОШИБКА: Шифр '" + cipherName + "' не поддерживается");
        QMessageBox::warning(this, "Ошибка", "Этот шифр еще не реализован");
        return;
    }

    statusLabel->setText("Выполняется шифрование...");
    statusLabel->setStyleSheet("padding: 8px; background-color: #ffffcc; border: 1px solid #ffcc00; border-radius: 3px; color: black;");

    try {
        logToConsole("\n════════════════════════════════════════");
        logToConsole("ШИФРОВАНИЕ: " + cipherName);
        logToConsole("Входной текст: " + inputText);

        // Получаем параметры
        if (cipherName == "Шифр Цезаря") {
            logToConsole("Сдвиг: " + QString::number(getCaesarShift()));
        }
        else if (cipherName == "Виженер (самоключ)") {
            logToConsole("Начальный символ: " + QString(getVigenereStartChar()));
        }
        else if (cipherName == "Белазо") {
            logToConsole("Ключ: " + getVigenereKey());
        }

        // Выполняем шифрование
        CipherResult result = encryptors[cipherName](inputText);

        // Выводим результат
        outputTextEdit->setText(result.result);

        // Используем ваш formatter для красивого вывода
        QString formatted = StepFormatter::formatResultOnly(result, 5);
        logToConsole("Результат: " + formatted);

        // Детализация шагов
        if (!result.steps.isEmpty()) {
            logToConsole("--- Детализация (" + QString::number(result.steps.size()) + " шагов) ---");

            // Показываем первые 3 шага и последние 2
            int stepsToShow = qMin(5, result.steps.size());
            for (int i = 0; i < stepsToShow; i++) {
                const CipherStep& step = result.steps[i];
                logToConsole(QString("  [%1] %2 → %3")
                    .arg(step.index + 1)
                    .arg(step.originalChar)
                    .arg(step.resultValue));
            }

            if (result.steps.size() > 5) {
                logToConsole("  ... и еще " + QString::number(result.steps.size() - 5) + " шагов");
            }
        }

        logToConsole("════════════════════════════════════════\n");

        statusLabel->setText("Шифрование завершено! Символов: " + QString::number(result.steps.size()));
        statusLabel->setStyleSheet("padding: 8px; background-color: #ccffcc; border: 1px solid #00cc00; border-radius: 3px; color: black;");

    } catch (const std::exception& e) {
        QString error = QString("Ошибка: %1").arg(e.what());
        logToConsole("КРИТИЧЕСКАЯ ОШИБКА: " + error);
        QMessageBox::critical(this, "Ошибка", error);

        statusLabel->setText("Ошибка при шифровании!");
        statusLabel->setStyleSheet("padding: 8px; background-color: #ffcccc; border: 1px solid #ff0000; border-radius: 3px; color: black;");
    }
}

void MainWindow::onDecryptClicked() {
    QString cipherName = cipherComboBox->currentText();
    QString inputText = inputTextEdit->toPlainText().trimmed();

    if (inputText.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для дешифрования!");
        return;
    }

    if (!decryptors.contains(cipherName)) {
        logToConsole("ОШИБКА: Шифр '" + cipherName + "' не поддерживает дешифрование");
        QMessageBox::warning(this, "Ошибка", "Этот шифр еще не реализован");
        return;
    }

    statusLabel->setText("Выполняется дешифрование...");
    statusLabel->setStyleSheet("padding: 8px; background-color: #ffffcc; border: 1px solid #ffcc00; border-radius: 3px; color: black;");

    try {
        logToConsole("\n════════════════════════════════════════");
        logToConsole("ДЕШИФРОВАНИЕ: " + cipherName);
        logToConsole("Входной текст: " + inputText);

        // Выполняем дешифрование
        CipherResult result = decryptors[cipherName](inputText);

        // Выводим результат
        outputTextEdit->setText(result.result);

        logToConsole("Результат: " + result.result);
        logToConsole("════════════════════════════════════════\n");

        statusLabel->setText("Дешифрование завершено!");
        statusLabel->setStyleSheet("padding: 8px; background-color: #ccffcc; border: 1px solid #00cc00; border-radius: 3px; color: black;");

    } catch (const std::exception& e) {
        QString error = QString("Ошибка: %1").arg(e.what());
        logToConsole("КРИТИЧЕСКАЯ ОШИБКА: " + error);
        QMessageBox::critical(this, "Ошибка", error);

        statusLabel->setText("Ошибка при дешифровании!");
        statusLabel->setStyleSheet("padding: 8px; background-color: #ffcccc; border: 1px solid #ff0000; border-radius: 3px; color: black;");
    }
}

void MainWindow::onClearClicked() {
    inputTextEdit->clear();
    outputTextEdit->clear();
    debugConsole->clear();
    statusLabel->setText("Все поля очищены. Выберите шифр.");
    statusLabel->setStyleSheet("padding: 8px; background-color: #e8e8e8; border: 1px solid #ccc; border-radius: 3px; color: black;");
    logToConsole("=== Все поля очищены ===");
}

void MainWindow::logToConsole(const QString& message) {
    // Двойной вывод
    debugConsole->append(message);
    std::cout << message.toStdString() << std::endl;
}
