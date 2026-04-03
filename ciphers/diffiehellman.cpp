#include "diffiehellman.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QGroupBox>
#include <QFrame>
#include <QTimer>
#include <QDebug>
#include <random>
#include <cmath>

// ==================== Вспомогательные функции ====================

bool DiffieHellmanCipher::isPrime(uint64_t n, int k) const
{
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0) return false;

    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, n - 2);

    for (int i = 0; i < k; ++i) {
        uint64_t a = dist(gen);
        uint64_t x = modPow(a, d, n);

        if (x == 1 || x == n - 1) continue;

        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = modPow(x, 2, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

bool DiffieHellmanCipher::isPrimeStatic(uint64_t n, int k)
{
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0) return false;

    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, n - 2);

    for (int i = 0; i < k; ++i) {
        uint64_t a = dist(gen);
        uint64_t x = DiffieHellmanCipher::modPowStatic(a, d, n);

        if (x == 1 || x == n - 1) continue;

        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = DiffieHellmanCipher::modPowStatic(x, 2, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

uint64_t DiffieHellmanCipher::gcd(uint64_t a, uint64_t b) const
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t DiffieHellmanCipher::gcdStatic(uint64_t a, uint64_t b)
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t DiffieHellmanCipher::modPow(uint64_t base, uint64_t exp, uint64_t mod) const
{
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

uint64_t DiffieHellmanCipher::modPowStatic(uint64_t base, uint64_t exp, uint64_t mod)
{
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

uint64_t DiffieHellmanCipher::generatePrimeStatic(int bits)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1 << (bits - 1), (1 << bits) - 1);

    uint64_t candidate;
    do {
        candidate = dist(gen);
        if (candidate % 2 == 0) candidate++;
    } while (!isPrimeStatic(candidate, 10));

    return candidate;
}

uint64_t DiffieHellmanCipher::generateRandomStatic(uint64_t max)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, max - 1);
    return dist(gen);
}

// ==================== Конструктор ====================

DiffieHellmanCipher::DiffieHellmanCipher() {}

// ==================== Encrypt (не используется) ====================

CipherResult DiffieHellmanCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.result = "Протокол Диффи-Хеллмана не предназначен для шифрования.\n"
                    "Используйте расширенные настройки для обмена ключами.";
    return result;
}

// ==================== Decrypt (не используется) ====================

CipherResult DiffieHellmanCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.result = "Протокол Диффи-Хеллмана не предназначен для расшифрования.\n"
                    "Используйте расширенные настройки для обмена ключами.";
    return result;
}

// ==================== Регистратор ====================

DiffieHellmanCipherRegister::DiffieHellmanCipherRegister()
{
    CipherFactory::instance().registerCipher(
        28,
        "Диффи-Хеллман (обмен ключами)",
        []() -> CipherInterface* { return new DiffieHellmanCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "diffiehellman",
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(8, 8, 8, 8);

            // ==================== Заголовок ====================
            QLabel* title = new QLabel("Протокол Диффи-Хеллмана");
            title->setStyleSheet("font-weight: bold; font-size: 13px;");
            title->setAlignment(Qt::AlignCenter);
            mainLayout->addWidget(title);

            // ==================== Общие параметры n и a ====================
            QHBoxLayout* commonLayout = new QHBoxLayout();
            commonLayout->setSpacing(10);

            QLabel* nLabel = new QLabel("n:");
            nLabel->setFixedWidth(25);
            QLineEdit* nEdit = new QLineEdit();
            nEdit->setObjectName("n");
            nEdit->setPlaceholderText("23");
            nEdit->setFixedWidth(120);
            nEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), nEdit));
            commonLayout->addWidget(nLabel);
            commonLayout->addWidget(nEdit);
            commonLayout->addStretch();

            QLabel* aLabel = new QLabel("a:");
            aLabel->setFixedWidth(20);
            QLineEdit* aEdit = new QLineEdit();
            aEdit->setObjectName("a");
            aEdit->setPlaceholderText("5");
            aEdit->setFixedWidth(120);
            aEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), aEdit));
            commonLayout->addWidget(aLabel);
            commonLayout->addWidget(aEdit);
            commonLayout->addStretch();

            mainLayout->addLayout(commonLayout);

            // ==================== Сторона 1 и Сторона 2 ====================
            QHBoxLayout* sidesLayout = new QHBoxLayout();
            sidesLayout->setSpacing(15);

            // ----- Сторона 1 -----
            QGroupBox* side1Group = new QGroupBox("Сторона 1");
            side1Group->setStyleSheet("QGroupBox { font-weight: bold; }");
            side1Group->setFixedWidth(280);
            QVBoxLayout* side1Layout = new QVBoxLayout(side1Group);
            side1Layout->setSpacing(6);
            side1Layout->setContentsMargins(8, 10, 8, 10);

            // KA - строка
            QHBoxLayout* kaLayout = new QHBoxLayout();
            QLabel* kaLabel = new QLabel("KA:");
            kaLabel->setFixedWidth(30);
            QLineEdit* kaEdit = new QLineEdit();
            kaEdit->setObjectName("ka");
            kaEdit->setPlaceholderText("секрет");
            kaLayout->addWidget(kaLabel);
            kaLayout->addWidget(kaEdit);
            side1Layout->addLayout(kaLayout);

            // Кнопка генерации KA
            QPushButton* generateKaButton = new QPushButton("Сген. KA");
            generateKaButton->setObjectName("generateKaButton");
            generateKaButton->setCursor(Qt::PointingHandCursor);
            generateKaButton->setFixedHeight(25);
            side1Layout->addWidget(generateKaButton);

            // YA - строка
            QHBoxLayout* yaLayout = new QHBoxLayout();
            QLabel* yaLabel = new QLabel("YA:");
            yaLabel->setFixedWidth(30);
            QLineEdit* yaEdit = new QLineEdit();
            yaEdit->setObjectName("ya");
            yaEdit->setReadOnly(true);
            yaEdit->setPlaceholderText("a^KA mod n");
            yaLayout->addWidget(yaLabel);
            yaLayout->addWidget(yaEdit);
            side1Layout->addLayout(yaLayout);

            // Кнопка вычисления YA
            QPushButton* computeYaButton = new QPushButton("Выч. YA");
            computeYaButton->setObjectName("computeYaButton");
            computeYaButton->setCursor(Qt::PointingHandCursor);
            computeYaButton->setFixedHeight(25);
            side1Layout->addWidget(computeYaButton);

            // Разделитель
            QFrame* line1 = new QFrame();
            line1->setFrameShape(QFrame::HLine);
            line1->setFixedHeight(1);
            side1Layout->addWidget(line1);
            side1Layout->addSpacing(4);

            // Полученный YB
            QHBoxLayout* ybReceivedLayout = new QHBoxLayout();
            QLabel* ybReceivedLabel = new QLabel("YB от 2:");
            ybReceivedLabel->setFixedWidth(50);
            QLineEdit* ybReceivedEdit = new QLineEdit();
            ybReceivedEdit->setObjectName("ybReceived");
            ybReceivedEdit->setReadOnly(true);
            ybReceivedEdit->setPlaceholderText("---");
            ybReceivedLayout->addWidget(ybReceivedLabel);
            ybReceivedLayout->addWidget(ybReceivedEdit);
            side1Layout->addLayout(ybReceivedLayout);

            // ----- Сторона 2 -----
            QGroupBox* side2Group = new QGroupBox("Сторона 2");
            side2Group->setStyleSheet("QGroupBox { font-weight: bold; }");
            side2Group->setFixedWidth(280);
            QVBoxLayout* side2Layout = new QVBoxLayout(side2Group);
            side2Layout->setSpacing(6);
            side2Layout->setContentsMargins(8, 10, 8, 10);

            // KB - строка
            QHBoxLayout* kbLayout = new QHBoxLayout();
            QLabel* kbLabel = new QLabel("KB:");
            kbLabel->setFixedWidth(30);
            QLineEdit* kbEdit = new QLineEdit();
            kbEdit->setObjectName("kb");
            kbEdit->setPlaceholderText("секрет");
            kbLayout->addWidget(kbLabel);
            kbLayout->addWidget(kbEdit);
            side2Layout->addLayout(kbLayout);

            // Кнопка генерации KB
            QPushButton* generateKbButton = new QPushButton("Сген. KB");
            generateKbButton->setObjectName("generateKbButton");
            generateKbButton->setCursor(Qt::PointingHandCursor);
            generateKbButton->setFixedHeight(25);
            side2Layout->addWidget(generateKbButton);

            // YB - строка
            QHBoxLayout* ybLayout = new QHBoxLayout();
            QLabel* ybLabel = new QLabel("YB:");
            ybLabel->setFixedWidth(30);
            QLineEdit* ybEdit = new QLineEdit();
            ybEdit->setObjectName("yb");
            ybEdit->setReadOnly(true);
            ybEdit->setPlaceholderText("a^KB mod n");
            ybLayout->addWidget(ybLabel);
            ybLayout->addWidget(ybEdit);
            side2Layout->addLayout(ybLayout);

            // Кнопка вычисления YB
            QPushButton* computeYbButton = new QPushButton("Выч. YB");
            computeYbButton->setObjectName("computeYbButton");
            computeYbButton->setCursor(Qt::PointingHandCursor);
            computeYbButton->setFixedHeight(25);
            side2Layout->addWidget(computeYbButton);

            // Разделитель
            QFrame* line2 = new QFrame();
            line2->setFrameShape(QFrame::HLine);
            line2->setFixedHeight(1);
            side2Layout->addWidget(line2);
            side2Layout->addSpacing(4);

            // Полученный YA
            QHBoxLayout* yaReceivedLayout = new QHBoxLayout();
            QLabel* yaReceivedLabel = new QLabel("YA от 1:");
            yaReceivedLabel->setFixedWidth(50);
            QLineEdit* yaReceivedEdit = new QLineEdit();
            yaReceivedEdit->setObjectName("yaReceived");
            yaReceivedEdit->setReadOnly(true);
            yaReceivedEdit->setPlaceholderText("---");
            yaReceivedLayout->addWidget(yaReceivedLabel);
            yaReceivedLayout->addWidget(yaReceivedEdit);
            side2Layout->addLayout(yaReceivedLayout);

            sidesLayout->addWidget(side1Group);
            sidesLayout->addWidget(side2Group);
            mainLayout->addLayout(sidesLayout);

            // ==================== Кнопки действий ====================
            QHBoxLayout* buttonsLayout = new QHBoxLayout();
            buttonsLayout->setSpacing(10);

            QPushButton* exchangeButton = new QPushButton("Обмен ключами");
            exchangeButton->setObjectName("exchangeButton");
            exchangeButton->setCursor(Qt::PointingHandCursor);
            exchangeButton->setFixedHeight(30);
            buttonsLayout->addWidget(exchangeButton);

            QPushButton* computeButton = new QPushButton("Вычислить ключ");
            computeButton->setObjectName("computeButton");
            computeButton->setCursor(Qt::PointingHandCursor);
            computeButton->setFixedHeight(30);
            buttonsLayout->addWidget(computeButton);

            QPushButton* resetButton = new QPushButton("Сброс");
            resetButton->setObjectName("resetButton");
            resetButton->setCursor(Qt::PointingHandCursor);
            resetButton->setFixedHeight(30);
            buttonsLayout->addWidget(resetButton);

            mainLayout->addLayout(buttonsLayout);

            // ==================== Результат ====================
            QGroupBox* resultGroup = new QGroupBox("Результат");
            resultGroup->setStyleSheet("QGroupBox { font-weight: bold; }");
            QVBoxLayout* resultLayout = new QVBoxLayout(resultGroup);
            resultLayout->setSpacing(6);
            resultLayout->setContentsMargins(8, 10, 8, 10);

            QLabel* formulasLabel = new QLabel("K = YB^KA mod n = YA^KB mod n");
            formulasLabel->setStyleSheet("font-family: monospace; font-size: 10px;");
            formulasLabel->setAlignment(Qt::AlignCenter);
            resultLayout->addWidget(formulasLabel);

            QHBoxLayout* resultsLayout = new QHBoxLayout();
            resultsLayout->setSpacing(15);

            QLineEdit* k1ResultEdit = new QLineEdit();
            k1ResultEdit->setObjectName("k1Result");
            k1ResultEdit->setReadOnly(true);
            k1ResultEdit->setPlaceholderText("K сторона 1");
            resultsLayout->addWidget(k1ResultEdit);

            QLineEdit* k2ResultEdit = new QLineEdit();
            k2ResultEdit->setObjectName("k2Result");
            k2ResultEdit->setReadOnly(true);
            k2ResultEdit->setPlaceholderText("K сторона 2");
            resultsLayout->addWidget(k2ResultEdit);

            resultLayout->addLayout(resultsLayout);
            mainLayout->addWidget(resultGroup);

            // ==================== Статус ====================
            QLabel* statusLabel = new QLabel();
            statusLabel->setObjectName("statusLabel");
            statusLabel->setAlignment(Qt::AlignCenter);
            statusLabel->setFixedHeight(30);
            mainLayout->addWidget(statusLabel);

            layout->addWidget(paramsContainer);

            // Сохраняем виджеты
            widgets["n"] = nEdit;
            widgets["a"] = aEdit;
            widgets["ka"] = kaEdit;
            widgets["kb"] = kbEdit;
            widgets["ya"] = yaEdit;
            widgets["yb"] = ybEdit;
            widgets["yaReceived"] = yaReceivedEdit;
            widgets["ybReceived"] = ybReceivedEdit;
            widgets["k1Result"] = k1ResultEdit;
            widgets["k2Result"] = k2ResultEdit;
            widgets["statusLabel"] = statusLabel;
            widgets["generateKaButton"] = generateKaButton;
            widgets["generateKbButton"] = generateKbButton;
            widgets["computeYaButton"] = computeYaButton;
            widgets["computeYbButton"] = computeYbButton;
            widgets["exchangeButton"] = exchangeButton;
            widgets["computeButton"] = computeButton;
            widgets["resetButton"] = resetButton;

            // Функция красной вспышки
            auto flashRed = [](QWidget* target) {
                QWidget* flash = new QWidget(target);
                flash->setGeometry(target->rect());
                flash->setStyleSheet("background-color: rgba(255, 0, 0, 80);");
                flash->raise();
                flash->show();
                QTimer::singleShot(300, [flash]() { flash->deleteLater(); });
            };

            // Вычисление YA
            auto computeYA = [nEdit, aEdit, kaEdit, yaEdit]() {
                uint64_t n = nEdit->text().toULongLong();
                uint64_t a = aEdit->text().toULongLong();
                uint64_t ka = kaEdit->text().toULongLong();
                if (n == 0 || a == 0 || ka == 0 || ka >= n) return;
                yaEdit->setText(QString::number(DiffieHellmanCipher::modPowStatic(a, ka, n)));
            };

            // Вычисление YB
            auto computeYB = [nEdit, aEdit, kbEdit, ybEdit]() {
                uint64_t n = nEdit->text().toULongLong();
                uint64_t a = aEdit->text().toULongLong();
                uint64_t kb = kbEdit->text().toULongLong();
                if (n == 0 || a == 0 || kb == 0 || kb >= n) return;
                ybEdit->setText(QString::number(DiffieHellmanCipher::modPowStatic(a, kb, n)));
            };

            // Обмен
            auto exchangeKeys = [yaEdit, ybEdit, yaReceivedEdit, ybReceivedEdit]() {
                yaReceivedEdit->setText(yaEdit->text());
                ybReceivedEdit->setText(ybEdit->text());
            };

            // Показать ошибку
            auto showError = [statusLabel, flashRed, parent](const QString& msg) {
                statusLabel->setText(msg);
                statusLabel->setStyleSheet("color: red; font-weight: bold;");
                flashRed(parent->window());
            };

            // Показать успех
            auto showSuccess = [statusLabel](const QString& msg) {
                statusLabel->setText(msg);
                statusLabel->setStyleSheet("color: green; font-weight: bold;");
            };

            // Вычисление общего ключа
            auto computeSecret = [nEdit, yaReceivedEdit, ybReceivedEdit, kaEdit, kbEdit,
                                   k1ResultEdit, k2ResultEdit, showError, showSuccess]() {
                uint64_t n = nEdit->text().toULongLong();
                uint64_t ya = yaReceivedEdit->text().toULongLong();
                uint64_t yb = ybReceivedEdit->text().toULongLong();
                uint64_t ka = kaEdit->text().toULongLong();
                uint64_t kb = kbEdit->text().toULongLong();

                if (n == 0) { showError("Ошибка: нет n"); return; }
                if (ka == 0 || kb == 0) { showError("Ошибка: нет KA/KB"); return; }
                if (ya == 0 || yb == 0) { showError("Ошибка: выполните обмен"); return; }

                uint64_t k1 = DiffieHellmanCipher::modPowStatic(yb, ka, n);
                uint64_t k2 = DiffieHellmanCipher::modPowStatic(ya, kb, n);

                k1ResultEdit->setText(QString::number(k1));
                k2ResultEdit->setText(QString::number(k2));

                if (k1 == k2 && k1 != 0) {
                    showSuccess(QString("Общий ключ: %1").arg(k1));
                } else {
                    showError("Ключи не совпадают!");
                }
            };

            // Сигналы
            QObject::connect(generateKaButton, &QPushButton::clicked, [nEdit, kaEdit]() {
                uint64_t n = nEdit->text().toULongLong();
                if (n == 0) { QMessageBox::warning(nullptr, "Ошибка", "Введите n!"); return; }
                kaEdit->setText(QString::number(DiffieHellmanCipher::generateRandomStatic(n)));
            });

            QObject::connect(generateKbButton, &QPushButton::clicked, [nEdit, kbEdit]() {
                uint64_t n = nEdit->text().toULongLong();
                if (n == 0) { QMessageBox::warning(nullptr, "Ошибка", "Введите n!"); return; }
                kbEdit->setText(QString::number(DiffieHellmanCipher::generateRandomStatic(n)));
            });

            QObject::connect(computeYaButton, &QPushButton::clicked, computeYA);
            QObject::connect(computeYbButton, &QPushButton::clicked, computeYB);
            QObject::connect(exchangeButton, &QPushButton::clicked, exchangeKeys);
            QObject::connect(computeButton, &QPushButton::clicked, computeSecret);

            QObject::connect(resetButton, &QPushButton::clicked, [nEdit, aEdit, kaEdit, kbEdit,
                                                                   yaEdit, ybEdit, yaReceivedEdit, ybReceivedEdit,
                                                                   k1ResultEdit, k2ResultEdit, statusLabel]() {
                nEdit->clear();
                aEdit->clear();
                kaEdit->clear();
                kbEdit->clear();
                yaEdit->clear();
                ybEdit->clear();
                yaReceivedEdit->clear();
                ybReceivedEdit->clear();
                k1ResultEdit->clear();
                k2ResultEdit->clear();
                statusLabel->clear();
                statusLabel->setStyleSheet("");
            });
        }
    );
}

static DiffieHellmanCipherRegister diffieHellmanRegister;
