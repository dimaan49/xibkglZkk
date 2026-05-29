#include "rsasign.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "classes/numberlineedit.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <cmath>
#include <random>
#include <chrono>


// ==================== RSASignCipher Implementation ====================

RSASignCipher::RSASignCipher()
{
}




// ==================== Валидация параметров ====================
bool RSASignCipher::validateParameters(uint64_t p, uint64_t q, uint64_t e, QString& errorMessage) const
{
    const uint64_t ALPHABET_SIZE = 32;

    if (!CoreMath::isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }
    if (!CoreMath::isPrime(q)) {
        errorMessage = QString("Q = %1 не является простым числом").arg(q);
        return false;
    }
    if (p == q) {
        errorMessage = "P и Q должны быть разными числами";
        return false;
    }

    uint64_t n = p * q;
    if (n <= ALPHABET_SIZE) {
        errorMessage = QString("N = P × Q = %1 должно быть больше %2").arg(n).arg(ALPHABET_SIZE);
        return false;
    }

    uint64_t phi = (p - 1) * (q - 1);
    if (e <= 1 || e >= phi) {
        errorMessage = QString("E должно быть в диапазоне 1 < E < φ(N) = %1").arg(phi);
        return false;
    }
    if (CoreMath::gcd(e, phi) != 1) {
        errorMessage = QString("E и φ(N) = %1 не являются взаимно простыми").arg(phi);
        return false;
    }

    return true;
}



uint64_t RSASignCipher::generateEStatic(uint64_t phi)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, phi - 1);

    uint64_t e;
    do {
        e = dist(gen);
    } while (CoreMath::gcd(e, phi) != 1);

    return e;
}



// ==================== Шифрование с подписью ====================
CipherResult RSASignCipher::process(const QString& text, const QVariantMap& params, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(),
        QString("Начало %1").arg(encrypt ? "подписания RSA" : "проверки подписи RSA"),
        "Инициализация"));

    if (encrypt) {
        // === Подписание ===
        uint64_t p = params.value("p", 0).toULongLong();
        uint64_t q = params.value("q", 0).toULongLong();
        uint64_t e = params.value("e", 0).toULongLong();

        if (p == 0 || q == 0 || e == 0) {
            result.result = "ОШИБКА: Для подписания необходимо ввести P, Q и E";
            return result;
        }

        QString validationError;
        if (!validateParameters(p, q, e, validationError)) {
            result.result = "ОШИБКА: " + validationError;
            return result;
        }

        uint64_t n = p * q;
        uint64_t phi = (p - 1) * (q - 1);
        uint64_t d = CoreMath::modInverse(e, phi);

        if (e == d) {
            result.result = "ОШИБКА: Открытый ключ E равен закрытому ключу D!";
            return result;
        }

        steps.append(CipherStep(1, QChar(),
            QString("P=%1, Q=%2, E=%3, N=%4, φ(N)=%5, D=%6").arg(p).arg(q).arg(e).arg(n).arg(phi).arg(d),
            "Вычисление ключей"));

        QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);
        if (filteredText.isEmpty()) {
            result.result = "Нет букв для преобразования";
            return result;
        }

        steps.append(CipherStep(2, QChar(),
            QString("Сообщение: %1").arg(filteredText), "Подготовка данных"));

        int stepCounter = 3;
        uint64_t hash = CoreHash::quadraticHash(filteredText, n, &steps, stepCounter);
        stepCounter += filteredText.length() + 2;

        uint64_t signature = CoreMath::modPow(hash, d, n);

        steps.append(CipherStep(stepCounter++, QChar(),
            QString("Подпись: S = H^D mod N = %1^%2 mod %3 = %4")
                .arg(hash).arg(d).arg(n).arg(signature),
            "Создание подписи"));

        result.result = filteredText + " | " + QString::number(signature);

    } else {
        // === Проверка подписи ===
        uint64_t n = params.value("n", 0).toULongLong();
        uint64_t e = params.value("e", 0).toULongLong();

        if (n == 0 || e == 0) {
            result.result = "ОШИБКА: Не указаны N и E для проверки подписи";
            return result;
        }

        steps.append(CipherStep(1, QChar(),
            QString("N=%1, E=%2").arg(n).arg(e), "Параметры"));

        QString inputText = text.trimmed();
        int separatorPos = inputText.lastIndexOf("|");

        if (separatorPos == -1) {
            result.result = "ОШИБКА: Неверный формат. Ожидается: 'сообщение | подпись'";
            return result;
        }

        QString message = inputText.left(separatorPos).trimmed();
        QString signaturePart = inputText.mid(separatorPos + 1).trimmed();

        bool sigOk;
        uint64_t signature = signaturePart.toULongLong(&sigOk);
        if (!sigOk) {
            result.result = "ОШИБКА: Не удалось распознать подпись: " + signaturePart;
            return result;
        }

        steps.append(CipherStep(2, QChar(),
            QString("Сообщение: %1, Подпись: %2").arg(message).arg(signature),
            "Извлечение данных"));

        int stepCounter = 3;
        uint64_t computedHash = CoreHash::quadraticHash(message, n, &steps, stepCounter);
        stepCounter += message.length() + 2;

        uint64_t decryptedHash = CoreMath::modPow(signature, e, n);

        steps.append(CipherStep(stepCounter++, QChar(),
            QString("Расшифрованная подпись: H2 = S^E mod N = %1^%2 mod %3 = %4")
                .arg(signature).arg(e).arg(n).arg(decryptedHash),
            "Расшифрование подписи"));

        if (computedHash == decryptedHash) {
            steps.append(CipherStep(stepCounter++, QChar(),
                QString("✓ Подпись ВЕРНА! H1 = H2 = %1").arg(computedHash),
                "Проверка подписи — УСПЕШНО"));
            result.result = QString("✓ ПОДПИСЬ ВЕРНА!\n\nСообщение: %1").arg(message);
        } else {
            steps.append(CipherStep(stepCounter++, QChar(),
                QString("✗ Подпись НЕВЕРНА! H1=%1 ≠ H2=%2").arg(computedHash).arg(decryptedHash),
                "Проверка подписи — ОШИБКА"));
            result.result = QString("ОШИБКА ПОДПИСИ: H1=%1 ≠ H2=%2").arg(computedHash).arg(decryptedHash);
        }
    }

    result.steps = steps;
    return result;
}

CipherResult RSASignCipher::encrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, true);
}

CipherResult RSASignCipher::decrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, false);
}

// ==================== RSASignCipherRegister Implementation ====================

RSASignCipherRegister::RSASignCipherRegister()
{
    CipherFactory::instance().registerCipher(
        24,
        "RSA с цифровой подписью",
        []() -> CipherInterface* { return new RSASignCipher(); },
        CipherCategory::DigitalSignature
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        24,
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // P
            QHBoxLayout* pRow = new QHBoxLayout();
            QLabel* pLabel = new QLabel("P (простое число):");
            pLabel->setFixedWidth(130);
            NumberLineEdit* pEdit = new NumberLineEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("Простое число (например, 61)");
            pRow->addWidget(pLabel);
            pRow->addWidget(pEdit);
            pRow->addStretch();
            mainLayout->addLayout(pRow);

            // Q
            QHBoxLayout* qRow = new QHBoxLayout();
            QLabel* qLabel = new QLabel("Q (простое число):");
            qLabel->setFixedWidth(130);
            NumberLineEdit* qEdit = new NumberLineEdit();
            qEdit->setObjectName("q");
            qEdit->setPlaceholderText("Простое число (например, 53)");
            qRow->addWidget(qLabel);
            qRow->addWidget(qEdit);
            qRow->addStretch();
            mainLayout->addLayout(qRow);

            // E
            QHBoxLayout* eRow = new QHBoxLayout();
            QLabel* eLabel = new QLabel("E (открытый ключ):");
            eLabel->setFixedWidth(130);
            NumberLineEdit* eEdit = new NumberLineEdit();
            eEdit->setObjectName("e");
            eEdit->setPlaceholderText("Взаимно простое с φ(N) (например, 17)");
            eRow->addWidget(eLabel);
            eRow->addWidget(eEdit);
            eRow->addStretch();
            mainLayout->addLayout(eRow);

            QFrame* line = new QFrame();
            line->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line);

            // N
            QHBoxLayout* nRow = new QHBoxLayout();
            QLabel* nLabel = new QLabel("N (модуль):");
            nLabel->setFixedWidth(130);
            NumberLineEdit* nEdit = new NumberLineEdit();
            nEdit->setObjectName("n");
            nEdit->setPlaceholderText("N = P × Q");
            nRow->addWidget(nLabel);
            nRow->addWidget(nEdit);
            nRow->addStretch();
            mainLayout->addLayout(nRow);

            // Кнопка
            QPushButton* generateButton = new QPushButton("Сгенерировать ключи (16 бит)");
            generateButton->setObjectName("generateButton");
            generateButton->setCursor(Qt::PointingHandCursor);
            mainLayout->addWidget(generateButton);

            // Инфо
            QLabel* infoLabel = new QLabel(
                "RSA с цифровой подписью:\n"
                "• N = P × Q\n"
                "• φ(N) = (P-1) × (Q-1)\n"
                "• D = E⁻¹ mod φ(N) (закрытый ключ, вычисляется автоматически)\n"
                "• Подпись: S = H^D mod N (используются P, Q, E)\n"
                "• Проверка: H = S^E mod N (используются N, E)"
            );
            infoLabel->setStyleSheet("color: #666; font-style: italic; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            layout->addWidget(paramsContainer);

            widgets["p"] = pEdit;
            widgets["q"] = qEdit;
            widgets["e"] = eEdit;
            widgets["n"] = nEdit;
            widgets["generateButton"] = generateButton;

            QObject::connect(generateButton, &QPushButton::clicked, [pEdit, qEdit, eEdit, nEdit]() {
                uint64_t p = CoreMath::generatePrime(16);
                uint64_t q = CoreMath::generatePrime(16);
                uint64_t phi = (p - 1) * (q - 1);
                uint64_t e = RSASignCipher::generateEStatic(phi);
                uint64_t n = p * q;
                uint64_t d = CoreMath::modInverse(e, phi);

                pEdit->setValue(p);
                qEdit->setValue(q);
                eEdit->setValue(e);
                nEdit->setValue(n);

                QMessageBox::information(nullptr, "Ключи сгенерированы",
                    QString("P = %1\nQ = %2\nN = %3\nE = %4 (открытый)\nD = %5 (закрытый, сохраните)\n\nφ(N) = %6")
                        .arg(p).arg(q).arg(n).arg(e).arg(d).arg(phi));
            });
        }
    );
}

static RSASignCipherRegister rsaSignRegister;
