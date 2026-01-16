#ifndef ROUTECIPHER_H
#define ROUTECIPHER_H

#include "ciphercore.h"
#include <vector>
#include <QString>
#include <QVector>

class RouteCipher {
private:
    // Основной метод с полным набором параметров
    CipherResult encryptImpl(const QString& text,
                            int rows, int cols,
                            const QVector<Direction>& writeDirections,
                            const QVector<Direction>& readDirections,
                            const QVector<int>& rowOrder,
                            const QVector<int>& columnOrder);

    // Вспомогательные методы
    std::vector<std::vector<QChar>> fillTable(const QString& text,
                                             const QVector<Direction>& writeDirections,
                                             const QVector<int>& rowOrder,
                                             QVector<CipherStep>& steps) const;

    QString readTable(const std::vector<std::vector<QChar>>& table,
                     const QVector<Direction>& readDirections,
                     const QVector<int>& columnOrder,
                     QVector<CipherStep>& steps) const;

    QString tableToString(const std::vector<std::vector<QChar>>& table) const;
    void calculateOptimalSize(int textLength, int& optimalRows, int& optimalCols) const;
    QVector<int> normalizeOrder(const QVector<int>& order, int size, const QString& orderName) const;

public:
    RouteCipher() = default;

    // Текущий интерфейс (для обратной совместимости)
    CipherResult encrypt(const QString& text,
                        const QVector<Direction>& writeDirections,
                        const QVector<Direction>& readDirections,
                        int rows = 0, int cols = 0);

    // Новый интерфейс с конфигурацией
    CipherResult encrypt(const QString& text, const RouteCipherConfig& config);

    // Дешифрование (упрощенное)
    CipherResult decrypt(const QString& text,
                        const RouteCipherConfig& config);

    QString name() const;
    QString description() const;
};

#endif // ROUTECIPHER_H
