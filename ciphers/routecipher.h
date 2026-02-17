#ifndef ROUTECIPHER_H
#define ROUTECIPHER_H

#include "cipherinterface.h"
#include <vector>
#include <QString>
#include <QVector>

class RouteCipher : public CipherInterface
{
public:
    RouteCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override;
    QString description() const override;

private:
    // Внутренние методы остаются прежними
    CipherResult encryptImpl(const QString& text,
                            int rows, int cols,
                            const QVector<Direction>& writeDirections,
                            const QVector<Direction>& readDirections,
                            const QVector<int>& rowOrder,
                            const QVector<int>& columnOrder);

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

    // Фиксированные настройки по умолчанию
    QVector<Direction> getDefaultWriteDirections(int rows) const;
    QVector<Direction> getDefaultReadDirections(int cols) const;
};

class RouteCipherRegister
{
public:
    RouteCipherRegister();
};

#endif // ROUTECIPHER_H
