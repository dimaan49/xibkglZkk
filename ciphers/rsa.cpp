#include "rsa.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "numberlineedit.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <cmath>
#include <random>
#include <chrono>

// ==================== RSACipher Implementation ====================

RSACipher::RSACipher()
{
}


bool RSACipher::validateParameters(uint64_t p, uint64_t q, uint64_t e, QString& errorMessage) const
{
    const uint64_t ALPHABET_SIZE = 32;

    // Проверка 1: p и q должны быть простыми
    if (!CoreMath::isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }
    if (!CoreMath::isPrime(q)) {
        errorMessage = QString("Q = %1 не является простым числом").arg(q);
        return false;
    }

    // Проверка 2: p и q должны быть разными
    if (p == q) {
        errorMessage = "P и Q должны быть разными числами";
        return false;
    }

    // Проверка 3: N = P × Q должно быть больше мощности алфавита
    uint64_t n = p * q;
    if (n <= ALPHABET_SIZE) {
        errorMessage = QString("N = P × Q = %1 должно быть больше %2 (мощности алфавита). "
                               "Увеличьте P и Q или выберите другие простые числа.")
                           .arg(n).arg(ALPHABET_SIZE);
        return false;
    }

    // Проверка 4: вычисляем φ(N)
    uint64_t phi = (p - 1) * (q - 1);

    // Проверка 5: 1 < e < φ(N)
    if (e <= 1 || e >= phi) {
        errorMessage = QString("E должно быть в диапазоне 1 < E < φ(N) = %1").arg(phi);
        return false;
    }

    // Проверка 6: e и φ(N) взаимно просты
    if (CoreMath::gcd(e, phi) != 1) {
        errorMessage = QString("E и φ(N) = %1 не являются взаимно простыми").arg(phi);
        return false;
    }

    return true;
}




uint64_t RSACipher::generateEStatic(uint64_t phi)
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



CipherResult RSACipher::process(const QString& text, const QVariantMap& params, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = encrypt;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(),
        QString("Начало %1 RSA").arg(encrypt ? "шифрования" : "расшифрования"),
        "Инициализация"));

    if (encrypt) {
        // === Шифрование ===
        uint64_t p = params.value("p", 0).toULongLong();
        uint64_t q = params.value("q", 0).toULongLong();
        uint64_t e = params.value("e", 0).toULongLong();

        if (p == 0 || q == 0 || e == 0) {
            result.result = "ОШИБКА: Для шифрования необходимо ввести P, Q и E";
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
            QString("P=%1, Q=%2, E=%3, N=%4, D=%5").arg(p).arg(q).arg(e).arg(n).arg(d),
            "Параметры"));

        QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);
        if (filteredText.isEmpty()) {
            result.result = "Нет букв для преобразования";
            return result;
        }

        QVector<uint64_t> numbers = CipherUtils::textToNumbers<uint64_t>(filteredText, m_alphabet);

        QStringList encryptedParts;
        for (int i = 0; i < numbers.size(); ++i) {
            uint64_t enc = CoreMath::modPow(numbers[i], e, n);
            encryptedParts.append(QString::number(enc));

            steps.append(CipherStep(2 + i, QChar(),
                QString("'%1' = %2 → %2^%3 mod %4 = %5")
                    .arg(filteredText[i]).arg(numbers[i]).arg(e).arg(n).arg(enc),
                QString("Шаг %1").arg(i + 1)));
        }

        result.result = encryptedParts.join(" ");

    } else {
        // === Расшифрование ===
        uint64_t n = params.value("n", 0).toULongLong();
        uint64_t d = params.value("d", 0).toULongLong();

        if (n == 0 || d == 0) {
            result.result = "ОШИБКА: Не указаны N и D";
            return result;
        }

        if (n == d) {
            result.result = "ОШИБКА: N не должен быть равен D!";
            return result;
        }

        steps.append(CipherStep(1, QChar(),
            QString("N=%1, D=%2").arg(n).arg(d), "Параметры"));

        QString cleaned = text;
        cleaned.replace(',', ' ');
        QStringList parts = cleaned.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

        QVector<uint64_t> encryptedNumbers;
        for (const QString& part : parts) {
            bool ok;
            uint64_t num = part.toULongLong(&ok);
            if (ok) encryptedNumbers.append(num);
        }

        QVector<uint64_t> decryptedNumbers;
        for (int i = 0; i < encryptedNumbers.size(); ++i) {
            uint64_t dec = CoreMath::modPow(encryptedNumbers[i], d, n);
            decryptedNumbers.append(dec);

            steps.append(CipherStep(2 + i, QChar(),
                QString("%1^%2 mod %3 = %4")
                    .arg(encryptedNumbers[i]).arg(d).arg(n).arg(dec),
                QString("Шаг %1").arg(i + 1)));
        }

        result.result = CipherUtils::numbersToText(decryptedNumbers, m_alphabet);
    }

    result.steps = steps;
    return result;
}


CipherResult RSACipher::encrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, true);
}

CipherResult RSACipher::decrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, false);
}
// ==================== RSACipherRegister Implementation ====================

// В регистраторе RSA (в конце rsa.cpp)
RSACipherRegister::RSACipherRegister()
{
    CipherFactory::instance().registerCipher(
        21,
        "RSA",
        []() -> CipherInterface* { return new RSACipher(); },
        CipherCategory::Asymmetric
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        21,
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
        },
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // Строка P
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

            // Строка Q
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

            // Строка E (открытый ключ для шифрования)
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

            // Разделитель
            QFrame* line1 = new QFrame();
            line1->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line1);

            // Строка N (модуль) - для расшифрования
            QHBoxLayout* nRow = new QHBoxLayout();
            QLabel* nLabel = new QLabel("N (модуль):");
            nLabel->setFixedWidth(130);
            NumberLineEdit* nEdit = new NumberLineEdit();
            nEdit->setObjectName("n");
            nEdit->setPlaceholderText("N = P × Q (для расшифрования)");
            nRow->addWidget(nLabel);
            nRow->addWidget(nEdit);
            nRow->addStretch();
            mainLayout->addLayout(nRow);

            // Строка D (закрытый ключ) - для расшифрования
            QHBoxLayout* dRow = new QHBoxLayout();
            QLabel* dLabel = new QLabel("D (закрытый ключ):");
            dLabel->setFixedWidth(130);
            NumberLineEdit* dEdit = new NumberLineEdit();
            dEdit->setObjectName("d");
            dEdit->setPlaceholderText("D = E⁻¹ mod φ(N)");
            dRow->addWidget(dLabel);
            dRow->addWidget(dEdit);
            dRow->addStretch();
            mainLayout->addLayout(dRow);

            // Кнопка генерации ключей
            QPushButton* generateButton = new QPushButton("Сгенерировать ключи (16 бит)");
            generateButton->setObjectName("generateButton");
            generateButton->setCursor(Qt::PointingHandCursor);
            mainLayout->addWidget(generateButton);

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "RSA (Rivest-Shamir-Adleman):\n"
                "• N = P × Q\n"
                "• φ(N) = (P-1) × (Q-1)\n"
                "• D = E⁻¹ mod φ(N) (закрытый ключ)\n"
                "• Шифрование: C = M^E mod N\n"
                "• P и Q должны быть простыми и разными\n"
                "• E должен быть взаимно прост с φ(N)\n"
                "• Каждая буква → число 0-31"
            );
            infoLabel->setStyleSheet("color: #666; font-style: italic; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            layout->addWidget(paramsContainer);

            widgets["p"] = pEdit;
            widgets["q"] = qEdit;
            widgets["e"] = eEdit;
            widgets["n"] = nEdit;
            widgets["d"] = dEdit;
            widgets["generateButton"] = generateButton;

            // Подключаем генерацию ключей - используем СТАТИЧЕСКИЕ методы
            QObject::connect(generateButton, &QPushButton::clicked, [pEdit, qEdit, eEdit, nEdit, dEdit]() {
                uint64_t p = CoreMath::generatePrime(16);
                uint64_t q = CoreMath::generatePrime(16);
                uint64_t phi = (p - 1) * (q - 1);
                uint64_t e = RSACipher::generateEStatic(phi);

                // Вычисляем D (закрытый ключ)
                uint64_t n = p * q;
                uint64_t d = CoreMath::modInverse(e, phi);

                pEdit->setValue(p);
                qEdit->setValue(q);
                eEdit->setValue(e);
                nEdit->setValue(n);
                dEdit->setValue(d);

                QMessageBox::information(nullptr, "Ключи сгенерированы",
                    QString("Сгенерированы ключи:\n\n"
                            "P = %1\n"
                            "Q = %2\n"
                            "N = %3\n"
                            "E = %4 (открытый)\n"
                            "D = %5 (закрытый)\n\n"
                            "φ(N) = %6")
                        .arg(p).arg(q).arg(n).arg(e).arg(d).arg(phi));
            });
        }
    );
}

static RSACipherRegister rsaRegister;
