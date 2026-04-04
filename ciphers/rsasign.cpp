#include "rsasign.h"
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
#include <QDebug>
#include <cmath>
#include <random>
#include <chrono>

// ==================== NumberLineEdit ====================

NumberLineEditSign::NumberLineEditSign(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();
    QRegularExpression numRegex("^[0-9]{0,20}$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(numRegex, this);
    setValidator(validator);
    setPlaceholderText("Введите число");
}

void NumberLineEditSign::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("NumberLineEditSign { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void NumberLineEditSign::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) setValid(true);
    QLineEdit::focusInEvent(event);
}

uint64_t NumberLineEditSign::getValue() const
{
    QString text = this->text();
    if (text.isEmpty()) return 0;
    bool ok;
    uint64_t value = text.toULongLong(&ok);
    return ok ? value : 0;
}

void NumberLineEditSign::setValue(uint64_t value)
{
    setText(QString::number(value));
}

// ==================== RSASignCipher Implementation ====================

RSASignCipher::RSASignCipher()
{
}

bool RSASignCipher::isPrime(uint64_t n, int k) const
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

bool RSASignCipher::isPrimeStatic(uint64_t n, int k)
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

uint64_t RSASignCipher::gcd(uint64_t a, uint64_t b) const
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t RSASignCipher::gcdStatic(uint64_t a, uint64_t b)
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t RSASignCipher::modPow(uint64_t base, uint64_t exp, uint64_t mod) const
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

uint64_t RSASignCipher::modPowStatic(uint64_t base, uint64_t exp, uint64_t mod)
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

uint64_t RSASignCipher::modInverse(uint64_t e, uint64_t phi) const
{
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

    if (r > 1) return 0;
    if (t < 0) t += phi;
    return static_cast<uint64_t>(t);
}

// ==================== Хеш-функция квадратичной свертки ====================
uint64_t RSASignCipher::computeHash(const QString& text, uint64_t p, QVector<CipherStep>& steps, int stepOffset) const
{
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filtered.isEmpty()) return 0;

    uint64_t h = 0;

    if (steps.size() > 0) {
        steps.append(CipherStep(stepOffset, QChar(),
            QString("Начало вычисления хеша: h0 = 0, модуль p = %1").arg(p),
            "Хеширование"));
    }

    for (int i = 0; i < filtered.length(); ++i) {
        int charIndex = m_alphabet.indexOf(filtered[i]);
        uint64_t Mi = static_cast<uint64_t>(charIndex + 1);

        uint64_t old_h = h;
        uint64_t sum = (h + Mi) % p;
        h = (sum * sum) % p;

        if (steps.size() > 0) {
            steps.append(CipherStep(stepOffset + i + 1, QChar(),
                QString("  h%1 = (h%2 + M%3)^2 mod p = (%4 + %5)^2 mod %6 = %7^2 mod %6 = %8")
                    .arg(i + 1).arg(i).arg(i + 1)
                    .arg(old_h).arg(Mi).arg(p)
                    .arg(sum).arg(h),
                QString("Хеш шаг %1: буква '%2' (№%3)").arg(i + 1).arg(filtered[i]).arg(Mi)));
        }
    }

    if (steps.size() > 0) {
        steps.append(CipherStep(stepOffset + filtered.length() + 1, QChar(),
            QString("Итоговый хеш: H = %1").arg(h),
            "Хеш завершен"));
    }

    return h;
}

// ==================== Валидация параметров ====================
bool RSASignCipher::validateParameters(uint64_t p, uint64_t q, uint64_t e, uint64_t p_hash, QString& errorMessage) const
{
    const uint64_t ALPHABET_SIZE = 32;

    // Проверка модуля хеширования
    if (p_hash <= ALPHABET_SIZE) {
        errorMessage = QString("Модуль хеширования p = %1 должен быть больше мощности алфавита (%2)").arg(p_hash).arg(ALPHABET_SIZE);
        return false;
    }

    if (!isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }
    if (!isPrime(q)) {
        errorMessage = QString("Q = %1 не является простым числом").arg(q);
        return false;
    }
    if (p == q) {
        errorMessage = "P и Q должны быть разными числами";
        return false;
    }

    uint64_t n = p * q;
    if (n <= ALPHABET_SIZE) {
        errorMessage = QString("N = P × Q = %1 должно быть больше %2 (мощности алфавита)")
                           .arg(n).arg(ALPHABET_SIZE);
        return false;
    }

    uint64_t phi = (p - 1) * (q - 1);
    if (e <= 1 || e >= phi) {
        errorMessage = QString("E должно быть в диапазоне 1 < E < φ(N) = %1").arg(phi);
        return false;
    }
    if (gcd(e, phi) != 1) {
        errorMessage = QString("E и φ(N) = %1 не являются взаимно простыми").arg(phi);
        return false;
    }

    return true;
}

int RSASignCipher::charToNumber(QChar ch) const
{
    return m_alphabet.indexOf(ch);
}

QChar RSASignCipher::numberToChar(int num) const
{
    if (num >= 0 && num < m_alphabet.length()) {
        return m_alphabet[num];
    }
    return '?';
}

uint64_t RSASignCipher::encryptNumber(uint64_t m, uint64_t e, uint64_t n) const
{
    return modPow(m, e, n);
}

uint64_t RSASignCipher::decryptNumber(uint64_t c, uint64_t d, uint64_t n) const
{
    return modPow(c, d, n);
}

uint64_t RSASignCipher::generatePrimeStatic(int bits)
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

uint64_t RSASignCipher::generateEStatic(uint64_t phi)
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

QVector<uint64_t> RSASignCipher::textToNumbers(const QString& text) const
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

QString RSASignCipher::numbersToText(const QVector<uint64_t>& numbers) const
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


// ==================== Шифрование с подписью ====================
CipherResult RSASignCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;  // результат - текст, а не числа

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало подписания RSA", "Инициализация"));

    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t q = params.value("q", 0).toULongLong();
    uint64_t e = params.value("e", 0).toULongLong();

    if (p == 0 || q == 0 || e == 0) {
        result.result = "ОШИБКА: Для подписания необходимо ввести P, Q и E";
        return result;
    }

    // Проверка простоты P и Q
    if (!isPrime(p)) {
        result.result = QString("ОШИБКА: P = %1 не является простым числом").arg(p);
        return result;
    }
    if (!isPrime(q)) {
        result.result = QString("ОШИБКА: Q = %1 не является простым числом").arg(q);
        return result;
    }
    if (p == q) {
        result.result = "ОШИБКА: P и Q должны быть разными числами";
        return result;
    }

    uint64_t n = p * q;
    const uint64_t ALPHABET_SIZE = 32;
    if (n <= ALPHABET_SIZE) {
        result.result = QString("ОШИБКА: N = P × Q = %1 должно быть больше %2")
                           .arg(n).arg(ALPHABET_SIZE);
        return result;
    }

    uint64_t phi = (p - 1) * (q - 1);
    if (e <= 1 || e >= phi) {
        result.result = QString("ОШИБКА: E должно быть в диапазоне 1 < E < φ(N) = %1").arg(phi);
        return result;
    }
    if (gcd(e, phi) != 1) {
        result.result = QString("ОШИБКА: E и φ(N) = %1 не являются взаимно простыми").arg(phi);
        return result;
    }

    uint64_t d = modInverse(e, phi);


    // Проверка: e и d не должны быть равны
    if (e == d) {
        result.result = QString("ОШИБКА: Открытый ключ E (%1) равен закрытому ключу D (%2)! "
                                "Выберите другие простые числа P и Q или другую экспоненту E.\n"
                                "Это происходит, когда E² ≡ 1 (mod φ(N)).")
                            .arg(e).arg(d);
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: P=%1, Q=%2, E=%3, N=%4, φ(N)=%5, D=%6")
            .arg(p).arg(q).arg(e).arg(n).arg(phi).arg(d),
        "Вычисление ключей"));

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    steps.append(CipherStep(2, QChar(),
        QString("Сообщение: %1").arg(filteredText),
        "Подготовка данных"));

    // Вычисляем хеш с использованием N как модуля хеширования
    int stepCounter = 3;
    uint64_t hash = computeHash(filteredText, n, steps, stepCounter);
    stepCounter += filteredText.length() + 2;

    // Вычисляем подпись
    uint64_t signature = modPow(hash, d, n);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Подпись: S = H^D mod N = %1^%2 mod %3 = %4")
            .arg(hash).arg(d).arg(n).arg(signature),
        "Создание подписи"));

    // Формируем результат: само сообщение и подпись через разделитель
    QString finalResult = filteredText + " | " + QString::number(signature);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Результат: %1 | %2").arg(filteredText).arg(signature),
        "Завершение"));

    result.result = finalResult;
    result.steps = steps;

    return result;
}

// ==================== Расшифрование с проверкой подписи ====================
CipherResult RSASignCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало проверки подписи RSA", "Инициализация"));

    uint64_t n = params.value("n", 0).toULongLong();
    uint64_t e = params.value("e", 0).toULongLong();

    if (n == 0) {
        result.result = "ОШИБКА: Не указан модуль N";
        return result;
    }
    if (e == 0) {
        result.result = "ОШИБКА: Не указан открытый ключ E для проверки подписи";
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: N=%1, E=%2").arg(n).arg(e),
        "Проверка параметров"));

    // Разбираем входные данные: сообщение | подпись
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
        QString("Получено сообщение: %1").arg(message),
        "Извлечение сообщения"));

    steps.append(CipherStep(3, QChar(),
        QString("Получена подпись: %1").arg(signature),
        "Извлечение подписи"));

    // Вычисляем хеш сообщения
    int stepCounter = 4;
    uint64_t computedHash = computeHash(message, n, steps, stepCounter);
    stepCounter += message.length() + 2;

    // Расшифровываем подпись (получаем хеш)
    uint64_t decryptedHash = modPow(signature, e, n);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Расшифрованная подпись: H2 = S^E mod N = %1^%2 mod %3 = %4")
            .arg(signature).arg(e).arg(n).arg(decryptedHash),
        "Расшифрование подписи"));

    // Проверка
    if (computedHash == decryptedHash) {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("✓ Подпись ВЕРНА! H1 (%1) == H2 (%2)").arg(computedHash).arg(decryptedHash),
            "Проверка подписи - УСПЕШНО"));
        result.result = QString("✓ ПОДПИСЬ ВЕРНА!\n\nСообщение: %1").arg(message);
    } else {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("✗ Подпись НЕВЕРНА! H1 = %1 != H2 = %2").arg(computedHash).arg(decryptedHash),
            "Проверка подписи - ОШИБКА"));
        result.result = QString("ОШИБКА ПОДПИСИ: H1 = %1 != H2 = %2").arg(computedHash).arg(decryptedHash);
    }

    result.steps = steps;
    return result;
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

            // Заголовок для ПОДПИСАНИЯ
            QLabel* signTitle = new QLabel("Для ПОДПИСАНИЯ (создание подписи):");
            signTitle->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(signTitle);

            // Сетка для P, Q, E
            QGridLayout* gridLayout = new QGridLayout();
            gridLayout->setSpacing(8);

            // Строка 0: P и Q
            QLabel* pLabel = new QLabel("P (простое):");
            pLabel->setFixedWidth(100);
            QLineEdit* pEdit = new QLineEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("61");
            pEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), pEdit));

            QLabel* qLabel = new QLabel("Q (простое):");
            qLabel->setFixedWidth(100);
            QLineEdit* qEdit = new QLineEdit();
            qEdit->setObjectName("q");
            qEdit->setPlaceholderText("53");
            qEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), qEdit));

            gridLayout->addWidget(pLabel, 0, 0);
            gridLayout->addWidget(pEdit, 0, 1);
            gridLayout->addWidget(qLabel, 0, 2);
            gridLayout->addWidget(qEdit, 0, 3);

            // Строка 1: E
            QLabel* eLabel = new QLabel("E (открытый):");
            eLabel->setFixedWidth(100);
            QLineEdit* eEdit = new QLineEdit();
            eEdit->setObjectName("e");
            eEdit->setPlaceholderText("17");
            eEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), eEdit));

            gridLayout->addWidget(eLabel, 1, 0);
            gridLayout->addWidget(eEdit, 1, 1);

            mainLayout->addLayout(gridLayout);

            // Разделитель
            QFrame* line1 = new QFrame();
            line1->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line1);

            // Заголовок для ПРОВЕРКИ
            QLabel* verifyTitle = new QLabel("Для ПРОВЕРКИ подписи:");
            verifyTitle->setStyleSheet("font-weight: bold; color: #2c3e50; margin-top: 5px;");
            mainLayout->addWidget(verifyTitle);

            // Сетка для N и E
            QGridLayout* gridLayout2 = new QGridLayout();
            gridLayout2->setSpacing(8);

            // N (модуль) - вычисляется автоматически из P и Q
            QLabel* nLabel = new QLabel("N = P × Q (модуль):");
            nLabel->setFixedWidth(120);
            QLineEdit* nEdit = new QLineEdit();
            nEdit->setObjectName("n");
            nEdit->setReadOnly(true);
            nEdit->setPlaceholderText("Вычисляется автоматически");
            nEdit->setStyleSheet("QLineEdit { background-color: #f0f0f0; }");

            // E (открытая экспонента) - для проверки
            QLabel* eCheckLabel = new QLabel("E (открытый ключ):");
            eCheckLabel->setFixedWidth(100);
            QLineEdit* eCheckEdit = new QLineEdit();
            eCheckEdit->setObjectName("e");
            eCheckEdit->setPlaceholderText("Та же E");
            eCheckEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), eCheckEdit));

            gridLayout2->addWidget(nLabel, 0, 0);
            gridLayout2->addWidget(nEdit, 0, 1);
            gridLayout2->addWidget(eCheckLabel, 0, 2);
            gridLayout2->addWidget(eCheckEdit, 0, 3);

            mainLayout->addLayout(gridLayout2);

            // Разделитель
            QFrame* line2 = new QFrame();
            line2->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line2);

            // Информация о хешировании
            QLabel* infoTitle = new QLabel("📌 Примечание:");
            infoTitle->setStyleSheet("font-weight: bold; color: #2c3e50; margin-top: 5px;");
            mainLayout->addWidget(infoTitle);

            QLabel* infoLabel = new QLabel(
                "Хеш-функция: hᵢ = (hᵢ₋₁ + Mᵢ)² mod N (N = P × Q)\n"
                "Подпись: S = H^D mod N\n"
                "Проверка: H = S^E mod N"
            );
            infoLabel->setStyleSheet("color: #666; font-size: 10px; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            // Кнопка генерации ключей
            QPushButton* generateButton = new QPushButton("🎲 Сгенерировать ключи (16 бит)");
            generateButton->setObjectName("generateButton");
            generateButton->setCursor(Qt::PointingHandCursor);
            mainLayout->addWidget(generateButton);

            layout->addWidget(paramsContainer);

            widgets["p"] = pEdit;
            widgets["q"] = qEdit;
            widgets["e"] = eEdit;
            widgets["n"] = nEdit;
            widgets["generateButton"] = generateButton;

            // Функция обновления N
            auto updateN = [pEdit, qEdit, nEdit]() {
                uint64_t p = pEdit->text().toULongLong();
                uint64_t q = qEdit->text().toULongLong();
                if (p > 0 && q > 0) {
                    uint64_t n = p * q;
                    nEdit->setText(QString::number(n));
                } else {
                    nEdit->clear();
                }
            };

            QObject::connect(pEdit, &QLineEdit::textChanged, [updateN](const QString&) { updateN(); });
            QObject::connect(qEdit, &QLineEdit::textChanged, [updateN](const QString&) { updateN(); });

            // Генерация ключей
            QObject::connect(generateButton, &QPushButton::clicked, [pEdit, qEdit, eEdit, nEdit]() {
                uint64_t p = RSASignCipher::generatePrimeStatic(16);
                uint64_t q = RSASignCipher::generatePrimeStatic(16);
                uint64_t phi = (p - 1) * (q - 1);
                uint64_t e = RSASignCipher::generateEStatic(phi);
                uint64_t n = p * q;

                // Вычисляем D через временный объект
                RSASignCipher temp;
                uint64_t d = temp.modInverse(e, phi);

                pEdit->setText(QString::number(p));
                qEdit->setText(QString::number(q));
                eEdit->setText(QString::number(e));
                nEdit->setText(QString::number(n));

                QMessageBox::information(nullptr, "Ключи сгенерированы",
                    QString("P = %1\nQ = %2\nN = %3\nE = %4\n\n"
                            "D = %5")
                        .arg(p).arg(q).arg(n).arg(e).arg(d));
            });
        }
    );
}

static RSASignCipherRegister rsaSignRegister;
