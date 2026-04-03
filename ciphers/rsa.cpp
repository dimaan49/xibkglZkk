#include "rsa.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
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

// ==================== NumberLineEdit Implementation ====================

NumberLineEdit::NumberLineEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    QRegularExpression numRegex("^[0-9]{0,20}$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(numRegex, this);
    setValidator(validator);

    setPlaceholderText("Введите число");
}

void NumberLineEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("NumberLineEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void NumberLineEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

uint64_t NumberLineEdit::getValue() const
{
    QString text = this->text();
    if (text.isEmpty()) return 0;
    bool ok;
    uint64_t value = text.toULongLong(&ok);
    return ok ? value : 0;
}

void NumberLineEdit::setValue(uint64_t value)
{
    setText(QString::number(value));
}

// ==================== RSACipher Implementation ====================

RSACipher::RSACipher()
{
}

// Алгоритм Миллера-Рабина для проверки простоты
bool RSACipher::isPrime(uint64_t n, int k) const
{
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0) return false;

    // Записываем n-1 как d * 2^r
    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    // Генератор случайных чисел
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, n - 2);

    // Проводим k тестов
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

bool RSACipher::isPrimeStatic(uint64_t n, int k)
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
        uint64_t x = modPowStatic(a, d, n);

        if (x == 1 || x == n - 1) continue;

        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = modPowStatic(x, 2, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

uint64_t RSACipher::gcd(uint64_t a, uint64_t b) const
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t RSACipher::gcdStatic(uint64_t a, uint64_t b)
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t RSACipher::modPow(uint64_t base, uint64_t exp, uint64_t mod) const
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

uint64_t RSACipher::modPowStatic(uint64_t base, uint64_t exp, uint64_t mod)
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

uint64_t RSACipher::modInverse(uint64_t e, uint64_t phi) const
{
    // Расширенный алгоритм Евклида
    int64_t t = 0, new_t = 1;
    int64_t r = phi, new_r = e;

    while (new_r != 0) {
        int64_t quotient = r / new_r;
        int64_t temp_t = t;
        t = new_t;
        new_t = temp_t - quotient * new_t;

        int64_t temp_r = r;
        r = new_r;
        new_r = temp_r - quotient * new_r;
    }

    if (r > 1) return 0; // Не существует обратного
    if (t < 0) t += phi;
    return static_cast<uint64_t>(t);
}

bool RSACipher::validateParameters(uint64_t p, uint64_t q, uint64_t e, QString& errorMessage) const
{
    const uint64_t ALPHABET_SIZE = 32;

    // Проверка 1: p и q должны быть простыми
    if (!isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }
    if (!isPrime(q)) {
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
    if (gcd(e, phi) != 1) {
        errorMessage = QString("E и φ(N) = %1 не являются взаимно простыми").arg(phi);
        return false;
    }

    return true;
}

int RSACipher::charToNumber(QChar ch) const
{
    return m_alphabet.indexOf(ch);
}

QChar RSACipher::numberToChar(int num) const
{
    if (num >= 0 && num < m_alphabet.length()) {
        return m_alphabet[num];
    }
    return '?';
}


uint64_t RSACipher::encryptNumber(uint64_t m, uint64_t e, uint64_t n) const
{
    return modPow(m, e, n);
}

uint64_t RSACipher::decryptNumber(uint64_t c, uint64_t d, uint64_t n) const
{
    return modPow(c, d, n);
}

uint64_t RSACipher::generatePrimeStatic(int bits)
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



uint64_t RSACipher::generateEStatic(uint64_t phi)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, phi - 1);

    uint64_t e;
    do {
        e = dist(gen);
    } while (gcdStatic(e, phi) != 1);

    return e;
}

// Преобразование текста в числа (каждая буква -> число 0-31)
QVector<uint64_t> RSACipher::textToNumbers(const QString& text) const
{
    QVector<uint64_t> numbers;
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    for (int i = 0; i < filtered.length(); ++i) {
        int num = charToNumber(filtered[i]);
        if (num >= 0 && num < 32) {
            numbers.append(static_cast<uint64_t>(num));
        }
    }

    return numbers;
}

// Преобразование чисел в текст (каждое число 0-31 -> буква)
QString RSACipher::numbersToText(const QVector<uint64_t>& numbers) const
{
    QString result;

    for (uint64_t num : numbers) {
        if (num < static_cast<uint64_t>(m_alphabet.length())) {
            result.append(m_alphabet[static_cast<int>(num)]);
        } else {
            result.append('?');
        }
    }

    return result;
}

// Шифрование
CipherResult RSACipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования RSA", "Инициализация"));

    // Получаем параметры
    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t q = params.value("q", 0).toULongLong();
    uint64_t e = params.value("e", 0).toULongLong();

    if (p == 0 || q == 0 || e == 0) {
        result.result = "ОШИБКА: Для шифрования необходимо ввести P, Q и E";
        return result;
    }

    // Проверяем параметры
    QString validationError;
    if (!validateParameters(p, q, e, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: P=%1, Q=%2, E=%3").arg(p).arg(q).arg(e),
        "Проверка параметров"));

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t d = modInverse(e, phi);

    if (e == d) {
         result.result = "ОШИБКА: Открытый ключ E равен закрытому ключу D! "
                         "Выберите другие простые числа P и Q или другую экспоненту E.\n"
                         "Это происходит, когда E² ≡ 1 (mod φ(N)).";
         return result;
     }


    const uint64_t ALPHABET_SIZE = 32;
    if (n <= ALPHABET_SIZE) {
        result.result = QString("ОШИБКА: N = P × Q = %1 должно быть больше мощности алфавита (%2). "
                                "Увеличьте P и Q или выберите другие простые числа.")
                            .arg(n).arg(ALPHABET_SIZE);
        return result;
    }

    steps.append(CipherStep(2, QChar(),
        QString("N=%1, φ(N)=%2, D=%3").arg(n).arg(phi).arg(d),
        "Вычисление ключей"));

    // Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    steps.append(CipherStep(3, QChar(),
        QString("Входной текст: %1").arg(filteredText),
        "Подготовка данных"));

    // Преобразуем текст в числа (каждая буква -> число 0-31)
    QVector<uint64_t> numbers = textToNumbers(filteredText);

    // Показываем оригинальные числа
    QString numbersStr;
    for (int i = 0; i < numbers.size() && i < 20; ++i) {
        numbersStr += QString("%1(%2) ").arg(filteredText[i]).arg(numbers[i]);
    }
    if (numbers.size() > 20) numbersStr += "...";

    steps.append(CipherStep(4, QChar(),
        QString("Преобразовано в числа 0-31: %1").arg(numbersStr),
        "Преобразование текста"));

    // Шифруем каждое число
    QVector<uint64_t> encryptedNumbers;
    QVector<QString> stepDetails;

    for (int i = 0; i < numbers.size(); ++i) {
        uint64_t encrypted = encryptNumber(numbers[i], e, n);
        encryptedNumbers.append(encrypted);
        stepDetails.append(QString("Буква %1: '%2' = %3 → %3^%4 mod %5 = %6")
            .arg(i + 1)
            .arg(filteredText[i])
            .arg(numbers[i])
            .arg(e)
            .arg(n)
            .arg(encrypted));
    }

    // Формируем результат: просто склеиваем числа через пробел
    // Это самый простой и читаемый способ
    QString resultNumbers;
    for (int i = 0; i < encryptedNumbers.size(); ++i) {
        if (i > 0) resultNumbers += " ";
        resultNumbers += QString::number(encryptedNumbers[i]);
    }

    steps.append(CipherStep(5, QChar(),
        QString("Результат: %1").arg(resultNumbers.left(100) + (resultNumbers.length() > 100 ? "..." : "")),
        "Завершение"));

    // Добавляем детальные шаги (первые 10)
    for (int i = 0; i < stepDetails.size() && i < 10; ++i) {
        steps.append(CipherStep(6 + i, QChar(), stepDetails[i], QString("Шаг %1").arg(i + 1)));
    }

    if (stepDetails.size() > 10) {
        steps.append(CipherStep(6 + stepDetails.size(), QChar(),
            QString("... и еще %1 шагов").arg(stepDetails.size() - 10),
            "Пропущенные шаги"));
    }

    result.result = resultNumbers;  // Числа через пробел
    result.steps = steps;

    return result;
}

// расшифрование
CipherResult RSACipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало расшифрования RSA", "Инициализация"));

    // Получаем параметры - для расшифрования нужны N и D
    uint64_t n = params.value("n", 0).toULongLong();
    uint64_t d = params.value("d", 0).toULongLong();

    // Проверяем наличие ключей
    if (n == 0 || d == 0) {
        result.result = "ОШИБКА: Не указаны закрытый ключ D и модуль N";
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: N=%1, D=%2").arg(n).arg(d),
        "Проверка параметров"));

    // Разбираем входные числа (разделены пробелами или запятыми)
    QString inputText = text.trimmed();
    inputText.replace(',', ' ');
    inputText.replace('\n', ' ');

    QStringList parts = inputText.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

    QVector<uint64_t> encryptedNumbers;
    for (const QString& part : parts) {
        bool ok;
        uint64_t num = part.toULongLong(&ok);
        if (ok) {
            encryptedNumbers.append(num);
        }
    }

    steps.append(CipherStep(2, QChar(),
        QString("Получено %1 чисел для расшифрования").arg(encryptedNumbers.size()),
        "Подготовка данных"));

    // Расшифровываем каждое число
    QVector<uint64_t> decryptedNumbers;
    QVector<QString> stepDetails;

    for (int i = 0; i < encryptedNumbers.size(); ++i) {
        uint64_t decrypted = decryptNumber(encryptedNumbers[i], d, n);
        decryptedNumbers.append(decrypted);
        stepDetails.append(QString("Число %1: %2^%3 mod %4 = %5")
            .arg(i + 1)
            .arg(encryptedNumbers[i])
            .arg(d)
            .arg(n)
            .arg(decrypted));
    }

    // Показываем расшифрованные числа
    QString decryptedStr;
    for (int i = 0; i < decryptedNumbers.size() && i < 20; ++i) {
        decryptedStr += QString::number(decryptedNumbers[i]) + " ";
    }
    if (decryptedNumbers.size() > 20) decryptedStr += "...";

    steps.append(CipherStep(3, QChar(),
        QString("Расшифрованные числа: %1").arg(decryptedStr),
        "Расшифрованные числа"));

    // Преобразуем числа обратно в текст
    QString resultText = numbersToText(decryptedNumbers);

    steps.append(CipherStep(4, QChar(),
        QString("Результат: %1").arg(resultText),
        "Завершение"));

    // Добавляем детальные шаги (первые 10)
    for (int i = 0; i < stepDetails.size() && i < 10; ++i) {
        steps.append(CipherStep(5 + i, QChar(), stepDetails[i], QString("Шаг %1").arg(i + 1)));
    }

    if (stepDetails.size() > 10) {
        steps.append(CipherStep(5 + stepDetails.size(), QChar(),
            QString("... и еще %1 шагов").arg(stepDetails.size() - 10),
            "Пропущенные шаги"));
    }

    result.result = resultText;
    result.steps = steps;

    return result;
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
            widgets["generateButton"] = generateButton;

            // Подключаем генерацию ключей - используем СТАТИЧЕСКИЕ методы
            QObject::connect(generateButton, &QPushButton::clicked, [pEdit, qEdit, eEdit, nEdit, dEdit]() {
                uint64_t p = RSACipher::generatePrimeStatic(16);
                uint64_t q = RSACipher::generatePrimeStatic(16);
                uint64_t phi = (p - 1) * (q - 1);
                uint64_t e = RSACipher::generateEStatic(phi);

                // Вычисляем D (закрытый ключ)
                uint64_t n = p * q;
                RSACipher temp;
                uint64_t d = temp.modInverse(e, phi);

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
