#ifndef CIPHERCORE_H
#define CIPHERCORE_H

#include <QString>
#include <QVector>
#include <QChar>
#include <QLineEdit>
#include <QKeyEvent>
#include <QByteArray>

#include <random>
#include <cstdint>

// БАЗА
// Шаг преобразования одного символа
struct CipherStep {
    int index;
    QChar originalChar;
    QString resultValue;
    QString description;

    CipherStep(int idx = -1,
               QChar orig = QChar(),
               const QString& result = QString(),
               const QString& desc = QString())
        : index(idx),
          originalChar(orig),
          resultValue(result),
          description(desc)
    {}
};

// Полный результат шифрования
struct CipherResult {
    QString result;
    QVector<CipherStep> steps;
    QString alphabet;
    QString cipherName;
    bool isNumeric;

    CipherResult(const QString& res = QString(),
                 const QVector<CipherStep>& st = QVector<CipherStep>(),
                 const QString& alph = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"),
                 const QString& name = QStringLiteral(u"Атбаш"),
                 bool numeric = false)
        : result(res),
          steps(st),
          alphabet(alph),
          cipherName(name),
          isNumeric(numeric)
    {}
};

namespace CipherUtils {

// Константы алфавитов
const QString RUSSIAN_ALPHABET_32 = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
const QString HEX_ALPHABET = QStringLiteral(u"0123456789ABCDEF");

//Базовая валидация
    // Убирает все неалфавитные символы (только русские буквы)
    static QString filterAlphabetOnly(const QString& text, const QString& alphabet) {
        QString result;
        for (QChar ch : text.toUpper()) {
            if (alphabet.contains(ch)) {
                result.append(ch);
            }
        }
        return result;
    }

    inline int charToIndex(QChar ch, const QString& alphabet) {
        return alphabet.indexOf(ch.toUpper());
    }

    inline QChar indexToChar(int index, const QString& alphabet) {
        if (index < 0 || index >= alphabet.size()) return QChar();
        return alphabet[index];
    }

    template<typename T = int>
     inline QVector<T> textToNumbers(const QString& text, const QString& alphabet) {
         QString filtered = filterAlphabetOnly(text, alphabet);
         QVector<T> result;
         result.reserve(filtered.size());
         for (QChar ch : filtered) {
             result.append(static_cast<T>(charToIndex(ch, alphabet)));
         }
         return result;
     }

     // Преобразование: массив чисел → текст
     template<typename T>
     inline QString numbersToText(const QVector<T>& numbers, const QString& alphabet) {
         QString result;
         result.reserve(numbers.size());
         for (T num : numbers) {
             int idx = static_cast<int>(num);
             if (idx >= 0 && idx < alphabet.size()) {
                 result.append(alphabet[idx]);
             }
         }
         return result;
     }

}



namespace CoreHex {

    inline QString rusToHex(const QString& rusText) {
        return rusText.toUtf8().toHex();
    }

    inline QString hexToRus(const QString& hexText) {
        QString clean = hexText.simplified().remove(' ');
        QByteArray bytes = QByteArray::fromHex(clean.toLatin1());
        return QString::fromUtf8(bytes);
    }

    // Проверка, является ли строка корректной HEX (только 0-9, A-F, a-f)
    inline bool isValidHex(const QString& hex) {
        if (hex.isEmpty()) return true;
        for (QChar ch : hex) {
            if (!((ch >= '0' && ch <= '9') ||
                  (ch >= 'A' && ch <= 'F') ||
                  (ch >= 'a' && ch <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    // Нормализация HEX: удаление всех не-Hex символов, приведение к верхнему регистру
    inline QString normalizeHex(const QString& hex) {
        QString result;
        result.reserve(hex.size());
        for (QChar ch : hex) {
            if ((ch >= '0' && ch <= '9') ||
                (ch >= 'A' && ch <= 'F') ||
                (ch >= 'a' && ch <= 'f')) {
                result.append(ch.toUpper());
            }
        }
        return result;
    }

    // HEX → байты (QByteArray)
    inline QByteArray hexToBytes(const QString& hex) {
        return QByteArray::fromHex(normalizeHex(hex).toLatin1());
    }

    // HEX → байты (в существующий буфер)
    inline void hexToBytes(const QString& hex, uint8_t* out, int len) {
        QByteArray bytes = hexToBytes(hex);
        for (int i = 0; i < len && i < bytes.size(); ++i) {
            out[i] = static_cast<uint8_t>(bytes[i]);
        }
        // Если HEX короче len, остальное заполняем 0
        for (int i = bytes.size(); i < len; ++i) {
            out[i] = 0;
        }
    }

    // Байты → HEX
    inline QString bytesToHex(const uint8_t* data, int len) {
        QString result;
        for (int i = 0; i < len; ++i) {
            result.append(QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper());
        }
        return result;
    }

    // QByteArray → HEX
    inline QString bytesToHex(const QByteArray& bytes) {
        return bytesToHex(reinterpret_cast<const uint8_t*>(bytes.constData()), bytes.size());
    }

    // HEX (8 символов) → uint32_t
    inline uint32_t hexToUint32(const QString& hex) {
        bool ok;
        uint32_t value = normalizeHex(hex).toUInt(&ok, 16);
        return ok ? value : 0;
    }

    // uint32_t → HEX (8 символов, с ведущими нулями)
    inline QString uint32ToHex(uint32_t value) {
        return QString("%1").arg(value, 8, 16, QChar('0')).toUpper();
    }

    // HEX (16 символов) → uint64_t
    inline uint64_t hexToUint64(const QString& hex) {
        bool ok;
        uint64_t value = normalizeHex(hex).toULongLong(&ok, 16);
        return ok ? value : 0;
    }

    // uint64_t → HEX (16 символов, с ведущими нулями)
    inline QString uint64ToHex(uint64_t value) {
        return QString("%1").arg(value, 16, 16, QChar('0')).toUpper();
    }

    // PKCS#7 паддинг
        inline QByteArray pkcs7Pad(const QByteArray& data, int blockSize) {
            int padding = blockSize - (data.size() % blockSize);
            if (padding == 0) padding = blockSize;
            QByteArray padded = data;
            padded.append(padding, static_cast<char>(padding));
            return padded;
        }

        // PKCS#7 удаление паддинга
        inline QByteArray pkcs7Unpad(const QByteArray& data) {
            if (data.isEmpty()) return data;
            int padding = static_cast<int>(static_cast<uint8_t>(data[data.size() - 1]));
            if (padding <= 0 || padding > data.size()) return data;
            for (int i = data.size() - padding; i < data.size(); ++i) {
                if (static_cast<uint8_t>(data[i]) != padding) return data;
            }
            return data.left(data.size() - padding);
        }


}


namespace CoreMath {

    // Модульная арифметика (для uint64_t)
    inline uint64_t modAdd(uint64_t a, uint64_t b, uint64_t mod) {
        uint64_t sum = a + b;
        if (sum < a || sum >= mod) {
            sum -= mod;
        }
        return sum;
    }

    inline uint64_t modSub(uint64_t a, uint64_t b, uint64_t mod) {
        if (a >= b) {
            return a - b;
        }
        return mod - (b - a);
    }

    inline uint64_t modMul(uint64_t a, uint64_t b, uint64_t mod) {
        uint64_t result = 0;
        a %= mod;
        while (b > 0) {
            if (b & 1) {
                result = (result + a) % mod;
            }
            a = (a * 2) % mod;
            b >>= 1;
        }
        return result;
    }

    // Быстрое возведение в степень по модулю
    inline uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) {
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

    // Расширенный алгоритм Евклида
    inline int64_t extendedGcd(int64_t a, int64_t b, int64_t& x, int64_t& y) {
        if (b == 0) {
            x = 1;
            y = 0;
            return a;
        }
        int64_t x1, y1;
        int64_t gcd = extendedGcd(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return gcd;
    }

    // Обратное число по модулю
    inline uint64_t modInverse(uint64_t a, uint64_t mod) {
        int64_t x, y;
        int64_t g = extendedGcd(static_cast<int64_t>(a), static_cast<int64_t>(mod), x, y);
        if (g != 1) return 0;
        int64_t result = x % static_cast<int64_t>(mod);
        if (result < 0) result += mod;
        return static_cast<uint64_t>(result);
    }

    // НОД
    inline uint64_t gcd(uint64_t a, uint64_t b) {
        while (b != 0) {
            uint64_t temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    // Проверка простоты (Миллер-Рабин)
    inline bool isPrime(uint64_t n, int k = 10) {
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

    // Генерация случайного числа в диапазоне [0, max-1]
    inline uint64_t generateRandom(uint64_t max) {
        if (max <= 1) return 0;
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(0, max - 1);
        return dist(gen);
    }

    // Генерация случайного числа в диапазоне [min, max-1]
    inline uint64_t generateRandom(uint64_t min, uint64_t max) {
        if (min >= max) return min;
        return min + generateRandom(max - min);
    }

    // Генерация случайного простого числа заданной битности
    inline uint64_t generatePrime(int bits, int k = 10) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        uint64_t minVal = 1ULL << (bits - 1);
        uint64_t maxVal = (1ULL << bits) - 1;
        std::uniform_int_distribution<uint64_t> dist(minVal, maxVal);

        uint64_t candidate;
        do {
            candidate = dist(gen);
            if (candidate % 2 == 0) candidate++;
        } while (!isPrime(candidate, k));

        return candidate;
    }

    // Проверка, является ли g первообразным корнем по модулю p
    inline bool isPrimitiveRoot(uint64_t g, uint64_t p) {
        if (!isPrime(p)) return false;
        if (g <= 1 || g >= p) return false;

        uint64_t phi = p - 1;
        QVector<uint64_t> factors;
        uint64_t temp = phi;

        // Факторизация phi
        for (uint64_t i = 2; i * i <= temp; ++i) {
            if (temp % i == 0) {
                factors.append(i);
                while (temp % i == 0) temp /= i;
            }
        }
        if (temp > 1) factors.append(temp);

        // Проверка условия g^(phi/p) != 1 для всех простых делителей
        for (uint64_t factor : factors) {
            if (modPow(g, phi / factor, p) == 1) {
                return false;
            }
        }
        return true;
    }

    // Генерация первообразного корня по модулю p
    inline uint64_t generatePrimitiveRoot(uint64_t p) {
        if (!isPrime(p)) return 0;

        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(2, p - 1);

        uint64_t g;
        do {
            g = dist(gen);
        } while (!isPrimitiveRoot(g, p));

        return g;
    }
}


namespace CoreHash {

    // Квадратичная свертка: h₀ = 0, hᵢ = (hᵢ₋₁ + Mᵢ)² mod p
    // где Mᵢ = индекс буквы в алфавите + 1 (А=1, Б=2, ..., Я=32)
    inline uint64_t quadraticHash(const QString& text, uint64_t p,
                                   QVector<CipherStep>* steps = nullptr,
                                   int stepOffset = 0) {
        // Фильтруем только буквы алфавита (используем RUSSIAN_ALPHABET_32)
        const QString& alphabet = CipherUtils::RUSSIAN_ALPHABET_32;
        QString filtered = CipherUtils::filterAlphabetOnly(text, alphabet);

        if (filtered.isEmpty()) return 0;

        uint64_t h = 0;

        if (steps && steps->size() > 0) {
            steps->append(CipherStep(stepOffset, QChar(),
                QString("Начало вычисления хеша: h0 = 0, модуль p = %1").arg(p),
                "Хеширование"));
        }

        for (int i = 0; i < filtered.length(); ++i) {
            int charIndex = CipherUtils::charToIndex(filtered[i], alphabet);
            uint64_t Mi = static_cast<uint64_t>(charIndex + 1);

            uint64_t old_h = h;
            uint64_t sum = (h + Mi) % p;
            h = (sum * sum) % p;

            if (steps && steps->size() > 0) {
                steps->append(CipherStep(stepOffset + i + 1, QChar(),
                    QString("  h%1 = (h%2 + M%3)² mod p = (%4 + %5)² mod %6 = %7² mod %6 = %8")
                        .arg(i + 1).arg(i).arg(i + 1)
                        .arg(old_h).arg(Mi).arg(p)
                        .arg(sum).arg(h),
                    QString("Хеш шаг %1: буква '%2' (№%3)").arg(i + 1).arg(filtered[i]).arg(Mi)));
            }
        }

        if (steps && steps->size() > 0) {
            steps->append(CipherStep(stepOffset + filtered.length() + 1, QChar(),
                QString("Итоговый хеш: H = %1").arg(h),
                "Хеш завершен"));
        }

        return h;
    }
}

// Точка на эллиптической кривой
struct ECC_Point {
    uint64_t x;
    uint64_t y;
    bool isInfinity;

    ECC_Point() : x(0), y(0), isInfinity(true) {}
    ECC_Point(uint64_t x_, uint64_t y_) : x(x_), y(y_), isInfinity(false) {}

    bool operator==(const ECC_Point& other) const {
        if (isInfinity && other.isInfinity) return true;
        if (isInfinity != other.isInfinity) return false;
        return x == other.x && y == other.y;
    }

    bool operator!=(const ECC_Point& other) const {
        return !(*this == other);
    }

    QString toString() const {
        if (isInfinity) return "Infinity";
        return QString("(%1, %2)").arg(x).arg(y);
    }
};

// Арифметика эллиптических кривых
struct CoreCurves {
    // Сложение двух точек
    static ECC_Point pointAdd(const ECC_Point& P, const ECC_Point& Q, uint64_t p, uint64_t a) {
        if (P.isInfinity) return Q;
        if (Q.isInfinity) return P;

        uint64_t x1 = P.x % p;
        uint64_t y1 = P.y % p;
        uint64_t x2 = Q.x % p;
        uint64_t y2 = Q.y % p;

        // Точки равны → удвоение
        if (x1 == x2 && y1 == y2) {
            return pointDouble(P, p, a);
        }

        // x₁ == x₂ → P + Q = O (бесконечность)
        if (x1 == x2) {
            return ECC_Point();
        }

        // λ = (y₂ - y₁) / (x₂ - x₁) mod p
        uint64_t num = (y2 + p - y1) % p;
        uint64_t den = (x2 + p - x1) % p;
        uint64_t den_inv = CoreMath::modInverse(den, p);

        if (den_inv == 0) return ECC_Point();

        uint64_t lambda = CoreMath::modMul(num, den_inv, p);

        // x₃ = λ² - x₁ - x₂ mod p
        uint64_t lambda2 = CoreMath::modMul(lambda, lambda, p);
        uint64_t x3 = (lambda2 + p - x1 + p - x2) % p;

        // y₃ = λ(x₁ - x₃) - y₁ mod p
        uint64_t x_diff = (x1 + p - x3) % p;
        uint64_t y3 = (CoreMath::modMul(lambda, x_diff, p) + p - y1) % p;

        return ECC_Point(x3, y3);
    }

    // Удвоение точки
    static ECC_Point pointDouble(const ECC_Point& P, uint64_t p, uint64_t a) {
        if (P.isInfinity) return P;

        uint64_t x1 = P.x % p;
        uint64_t y1 = P.y % p;

        // y = 0 → касательная вертикальна → точка в бесконечности
        if (y1 == 0) return ECC_Point();

        // λ = (3x₁² + a) / (2y₁) mod p
        uint64_t x1_sq = CoreMath::modMul(x1, x1, p);
        uint64_t num = (3 * x1_sq + (a % p)) % p;
        uint64_t den = (2 * y1) % p;
        uint64_t den_inv = CoreMath::modInverse(den, p);

        if (den_inv == 0) return ECC_Point();

        uint64_t lambda = CoreMath::modMul(num, den_inv, p);

        // x₃ = λ² - 2x₁ mod p
        uint64_t lambda2 = CoreMath::modMul(lambda, lambda, p);
        uint64_t x3 = (lambda2 + p - (2 * x1) % p) % p;

        // y₃ = λ(x₁ - x₃) - y₁ mod p
        uint64_t x_diff = (x1 + p - x3) % p;
        uint64_t y3 = (CoreMath::modMul(lambda, x_diff, p) + p - y1) % p;

        return ECC_Point(x3, y3);
    }

    // Умножение точки на скаляр (алгоритм удвоения-сложения)
    static ECC_Point pointMultiply(const ECC_Point& P, uint64_t k, uint64_t p, uint64_t a) {
        if (k == 0 || P.isInfinity) return ECC_Point();

        ECC_Point result;      // точка в бесконечности
        ECC_Point base = P;
        uint64_t k_val = k;

        while (k_val > 0) {
            if (k_val & 1) {
                result = pointAdd(result, base, p, a);
            }
            base = pointDouble(base, p, a);
            k_val >>= 1;
        }

        return result;
    }

    // Проверка принадлежности точки кривой: y² ≡ x³ + a·x + b (mod p)
    static bool isPointOnCurve(const ECC_Point& P, uint64_t p, uint64_t a, uint64_t b) {
        if (P.isInfinity) return true;

        uint64_t left = CoreMath::modMul(P.y, P.y, p);
        uint64_t x3 = CoreMath::modMul(CoreMath::modMul(P.x, P.x, p), P.x, p);
        uint64_t ax = CoreMath::modMul(a, P.x, p);
        uint64_t right = (x3 + ax + (b % p)) % p;

        return left == right;
    }

    static ECC_Point parsePoint(const QString& str) {
        QString s = str.trimmed();
        if (s.isEmpty() || s == "inf" || s == "Infinity" || s == "O") {
            return ECC_Point(); // бесконечность
        }

        // Убираем скобки и пробелы
        s.remove('(').remove(')').remove(' ');

        QStringList parts = s.split(',');
        if (parts.size() < 2) return ECC_Point();

        bool ok1, ok2;
        uint64_t x = parts[0].toULongLong(&ok1);
        uint64_t y = parts[1].toULongLong(&ok2);

        if (!ok1 || !ok2) return ECC_Point();

        return ECC_Point(x, y);
    }

    static void computeCurveOrder(uint64_t p, uint64_t a, uint64_t b,
                                  uint64_t& curveOrder, uint64_t& subgroupOrder,
                                  uint64_t& cofactor, QString& log) {
        log.clear();
        log += "=== Вычисление порядка эллиптической кривой перебором ===\n\n";
        log += QString("Параметры: p = %1, a = %2, b = %3\n").arg(p).arg(a).arg(b);
        log += QString("Уравнение: y² = x³ + %1·x + %2 (mod %3)\n\n").arg(a).arg(b).arg(p);

        // Предвычисляем квадраты по модулю p
        QMap<uint64_t, QList<uint64_t>> squares;
        for (uint64_t y = 0; y < p; ++y) {
            uint64_t y2 = CoreMath::modMul(y, y, p);
            squares[y2].append(y);
        }

        // Перебор точек
        QVector<ECC_Point> points;
        for (uint64_t x = 0; x < p; ++x) {
            uint64_t x3 = CoreMath::modMul(CoreMath::modMul(x, x, p), x, p);
            uint64_t ax = CoreMath::modMul(a, x, p);
            uint64_t rhs = (x3 + ax + (b % p)) % p;

            if (squares.contains(rhs)) {
                for (uint64_t y : squares[rhs]) {
                    points.append(ECC_Point(x, y));
                }
            }
        }

        // +1 за точку в бесконечности
        curveOrder = points.size() + 1;

        // Находим наибольший простой делитель порядка кривой
        subgroupOrder = 1;
        for (uint64_t i = 2; i <= curveOrder; ++i) {
            if (curveOrder % i == 0 && CoreMath::isPrime(i)) {
                subgroupOrder = i;
            }
        }

        cofactor = curveOrder / subgroupOrder;

        log += QString("Количество точек: %1\n").arg(points.size());
        log += QString("n = #E = %1 = h · q\n").arg(curveOrder);
        log += QString("Кофактор h = %1\n").arg(cofactor);
        log += QString("Порядок подгруппы q = %1\n").arg(subgroupOrder);
        log += QString("Проверка: %1 = %2 · %3\n").arg(curveOrder).arg(cofactor).arg(subgroupOrder);
    }
};



enum Direction {
    LEFT_TO_RIGHT,    // Слева направо
    RIGHT_TO_LEFT,    // Справа налево
    TOP_TO_BOTTOM,    // Сверху вниз
    BOTTOM_TO_TOP     // Снизу вверх
};

// Шаг маршрутной перестановки
struct RouteStep {
    int stepNumber;
    QString action;  // "Запись" или "Чтение"
    QString route;   // Описание маршрута
    QString placed;  // Размещенные символы
    QString matrix;  // Состояние матрицы

    RouteStep(int num = 0,
             const QString& act = QString(),
             const QString& rt = QString(),
             const QString& pl = QString(),
             const QString& mat = QString())
        : stepNumber(num), action(act), route(rt), placed(pl), matrix(mat) {}
};

// Структура конфигурации для RouteCipher
struct RouteCipherConfig {
    int rows = 0;
    int cols = 0;
    QVector<Direction> writeDirections;  // Направления записи по строкам
    QVector<Direction> readDirections;   // Направления чтения по столбцам
    QVector<int> columnOrder;            // Порядок столбцов (пусто = обычный порядок)
    QVector<int> rowOrder;               // Порядок строк (пусто = обычный порядок)

    RouteCipherConfig() = default;

    // Вспомогательные конструкторы
    static RouteCipherConfig createSimple(int r, int c,
                                         Direction writeDir = LEFT_TO_RIGHT,
                                         Direction readDir = TOP_TO_BOTTOM) {
        RouteCipherConfig config;
        config.rows = r;
        config.cols = c;
        for (int i = 0; i < r; ++i) {
            config.writeDirections.append(writeDir);
        }
        for (int i = 0; i < c; ++i) {
            config.readDirections.append(readDir);
        }
        return config;
    }

    static RouteCipherConfig createSnake(int r, int c,
                                        Direction readDir = TOP_TO_BOTTOM) {
        RouteCipherConfig config;
        config.rows = r;
        config.cols = c;
        for (int i = 0; i < r; ++i) {
            config.writeDirections.append((i % 2 == 0) ? LEFT_TO_RIGHT : RIGHT_TO_LEFT);
        }
        for (int i = 0; i < c; ++i) {
            config.readDirections.append(readDir);
        }
        return config;
    }
};











#endif // CIPHERCORE_H
