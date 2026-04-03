#include "shannonpad.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "RestrictedSpinBox.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QSpinBox>
#include <QTimer>
#include <cmath>

// ==================== ValidatedLineEdit Implementation ====================

ValidatedLineEdit::ValidatedLineEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();
}

void ValidatedLineEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("ValidatedLineEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void ValidatedLineEdit::focusInEvent(QFocusEvent* event)
{
    // При получении фокуса сбрасываем красную подсветку
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

// ==================== ShannonPadCipher Implementation ====================

ShannonPadCipher::ShannonPadCipher()
{
}

CipherResult ShannonPadCipher::encrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, true);
}

CipherResult ShannonPadCipher::decrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, false);
}

bool ShannonPadCipher::validateParameters(int t0, int a, int c, QString& errorMessage)
{
    Q_UNUSED(t0) // T0 может быть любым, не проверяем

    const int m = ALPHABET_SIZE; // 32

    // Проверка 1: a - нечетное число
    if (a % 2 == 0) {
        errorMessage = "Параметр 'a' должен быть нечетным числом";
        return false;
    }

    // Проверка 2: с – взаимно просто с модулем m (НОД(c, m) = 1)
    // Для m=32 (2^5), взаимно простыми будут нечетные числа
    if (c % 2 == 0) {
        errorMessage = "Параметр 'c' должен быть нечетным (взаимно прост с 32)";
        return false;
    }

    // Проверка НОД через алгоритм Евклида
    int gcd = [](int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }(c, m);

    if (gcd != 1) {
        errorMessage = QString("Параметр 'c' должен быть взаимно прост с модулем 32 (НОД(%1, 32) = %2, требуется 1)")
                          .arg(c).arg(gcd);
        return false;
    }

    // Проверка 3: b = a – 1 кратно p для каждого простого p, делителя m
    // Делители m=32: простые числа - только 2
    int b = a - 1;
    if (b % 2 != 0) {
        errorMessage = "Параметр 'a' должен удовлетворять условию: (a-1) кратно 2";
        return false;
    }

    // Проверка 4: b кратно 4, если m кратно 4 (m=32 кратно 4)
    if (b % 4 != 0) {
        errorMessage = "Параметр 'a' должен удовлетворять условию: (a-1) кратно 4 (так как модуль 32 кратен 4)";
        return false;
    }

    if (a==1) {
        errorMessage = "Параметр 'a' не может быть равен 1";
        return false;
    }

    if (a==0) {
        errorMessage = "Параметр 'a' не может быть равен 0";
        return false;
    }

    return true;
}

QVector<int> ShannonPadCipher::generateGamma(int length, int t0, int a, int c)
{
    QVector<int> gamma;
    if (length <= 0) return gamma;

    const int m = ALPHABET_SIZE;
    int current = t0 % m; // Нормализуем T0 к диапазону 0-31
    if (current < 0) current += m;

    for (int i = 0; i < length; ++i) {
        gamma.append(current);
        // T(i+1) = (a * T(i) + c) mod m
        current = (a * current + c) % m;
        // Обработка отрицательных значений (на всякий случай)
        if (current < 0) current += m;
    }

    return gamma;
}

CipherResult ShannonPadCipher::process(const QString& text, const QVariantMap& params, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;

    // Получаем параметры
    int t0 = params.value("t0", 1).toInt();
    int a = params.value("a", 5).toInt();
    int c = params.value("c", 3).toInt();

    // Валидация параметров
    QString validationError;
    if (!validateParameters(t0, a, c, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    // Фильтруем только буквы алфавита
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    // Генерируем гамму той же длины, что и отфильтрованный текст
    QVector<int> gamma = generateGamma(filteredText.length(), t0, a, c);

    QString transformed;
    int n = m_alphabet.size();

    for (int i = 0; i < filteredText.length(); ++i) {
        QChar ch = filteredText[i];
        int textPos = m_alphabet.indexOf(ch);
        int gammaValue = gamma[i];

        int newPos;
        QString operation;

        if (encrypt) {
            // Шифрование: ci = (mi + ki) mod n
            newPos = (textPos + gammaValue) % n;
            operation = "+";
        } else {
            // Дешифрование: mi = (ci - ki + n) mod n
            newPos = (textPos - gammaValue + n) % n;
            operation = "-";
        }

        QChar newChar = m_alphabet[newPos];
        transformed.append(newChar);

        // Формируем описание шага
        QString stepDesc = QString("Шаг %1: %2[%3] %4 гамма[%5] = %6[%7] (T%8 = %9)")
            .arg(i + 1)
            .arg(ch).arg(textPos)
            .arg(operation)
            .arg(gammaValue)
            .arg(newChar).arg(newPos)
            .arg(i).arg(gammaValue);

        CipherStep step;
        step.index = i;
        step.originalChar = ch;
        step.resultValue = QString(newChar);
        step.description = stepDesc;
        result.steps.append(step);
    }

    // Добавляем информацию о гамме в результат
    QString gammaStr;
    for (int val : gamma) {
        gammaStr += QString::number(val) + " ";
    }

    CipherStep gammaStep;
    gammaStep.index = -1;
    gammaStep.originalChar = QChar();
    gammaStep.resultValue = gammaStr.trimmed();
    gammaStep.description = QString("Сгенерированная гамма (T0=%1, a=%2, c=%3):").arg(t0).arg(a).arg(c);
    result.steps.prepend(gammaStep);

    result.result = transformed;
    return result;
}

// shannonpad.cpp - только исправленная регистрация

ShannonPadCipherRegister::ShannonPadCipherRegister()
{
    // Регистрируем шифр в основной фабрике
    CipherFactory::instance().registerCipher(
        14,
        "Одноразовый блокнот Шеннона",
        []() -> CipherInterface* { return new ShannonPadCipher(); },
        CipherCategory::Gamma
    );

    // Регистрируем виджеты параметров (ГОРИЗОНТАЛЬНОЕ РАСПОЛОЖЕНИЕ С ПОДПИСЯМИ СЛЕВА)
    CipherWidgetFactory::instance().registerCipherWidgets(
        "shannon_pad",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            // Минимальный контейнер без лишних отступов
            QWidget* paramsContainer = new QWidget(parent);
            QHBoxLayout* mainLayout = new QHBoxLayout(paramsContainer);
            mainLayout->setSpacing(10);
            mainLayout->setContentsMargins(0, 0, 0, 0); // Убираем все отступы

            // T0 - начальное значение (подпись слева)
            QLabel* t0Label = new QLabel("T₀:");
            t0Label->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            RestrictedSpinBox* t0SpinBox = new RestrictedSpinBox();
            t0SpinBox->setRange(0, 31);
            t0SpinBox->setValue(1);
            t0SpinBox->setToolTip("Начальное значение генератора (0-31)");
            t0SpinBox->setObjectName("t0");
            t0SpinBox->setFixedWidth(70);
            t0SpinBox->setAlignment(Qt::AlignCenter);

            QHBoxLayout* t0Row = new QHBoxLayout();
            t0Row->setSpacing(5);
            t0Row->setContentsMargins(0, 0, 0, 0);
            t0Row->addWidget(t0Label);
            t0Row->addWidget(t0SpinBox);
            mainLayout->addLayout(t0Row);

            // a - множитель (подпись слева)
            QLabel* aLabel = new QLabel("a:");
            aLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            RestrictedSpinBox* aSpinBox = new RestrictedSpinBox();
            aSpinBox->setRange(1, 100);
            aSpinBox->setValue(5);
            aSpinBox->setToolTip("Множитель (должен быть нечетным)");
            aSpinBox->setObjectName("a");
            aSpinBox->setFixedWidth(70);
            aSpinBox->setAlignment(Qt::AlignCenter);

            QHBoxLayout* aRow = new QHBoxLayout();
            aRow->setSpacing(5);
            aRow->setContentsMargins(0, 0, 0, 0);
            aRow->addWidget(aLabel);
            aRow->addWidget(aSpinBox);
            mainLayout->addLayout(aRow);

            // c - приращение (подпись слева)
            QLabel* cLabel = new QLabel("c:");
            cLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            RestrictedSpinBox* cSpinBox = new RestrictedSpinBox();
            cSpinBox->setRange(1, 100);
            cSpinBox->setValue(3);
            cSpinBox->setToolTip("Приращение (должно быть нечетным и взаимно простым с 32)");
            cSpinBox->setObjectName("c");
            cSpinBox->setFixedWidth(70);
            cSpinBox->setAlignment(Qt::AlignCenter);

            QHBoxLayout* cRow = new QHBoxLayout();
            cRow->setSpacing(5);
            cRow->setContentsMargins(0, 0, 0, 0);
            cRow->addWidget(cLabel);
            cRow->addWidget(cSpinBox);
            mainLayout->addLayout(cRow);

            mainLayout->addStretch(); // Растяжение справа

            layout->addWidget(paramsContainer);

            // Добавляем информационную панель отдельно (можно убрать если не нужна)
            QLabel* infoLabel = new QLabel(
                "Условия: a - нечетное, c - нечетное, (a-1) кратно 4"
            );
            infoLabel->setStyleSheet("color: #666; font-style: italic; font-size: 10px; padding: 2px;");
            infoLabel->setWordWrap(true);
            layout->addWidget(infoLabel);

            // Сохраняем виджеты в карту
            widgets["t0"] = t0SpinBox;
            widgets["a"] = aSpinBox;
            widgets["c"] = cSpinBox;
        },
        nullptr // advancedCreator = nullptr
    );
}

// Статический экземпляр для автоматической регистрации при загрузке библиотеки
static ShannonPadCipherRegister shannonPadRegister;
