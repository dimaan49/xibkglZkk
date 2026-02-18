#ifndef COLUMNTRANSPOSITIONCIPHER_H
#define COLUMNTRANSPOSITIONCIPHER_H

#include "routecipher.h"
#include <QVector>
#include <QString>

class ColumnTranspositionCipher : public RouteCipher
{
public:
    ColumnTranspositionCipher();

    // Переопределяем виртуальные методы
    QString name() const override;
    QString description() const override;
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;

    // Метод для преобразования ключа в порядок столбцов
    static QVector<int> keyToColumnOrder(const QString& key, int columnCount, QString& errorMessage);

protected:
    // Делаем protected, чтобы дочерние классы могли использовать
    using RouteCipher::getDefaultWriteDirections;
    using RouteCipher::getDefaultReadDirections;
    using RouteCipher::encryptImpl;

private:
    static const QString RUSSIAN_ALPHABET;
};

#endif // COLUMNTRANSPOSITIONCIPHER_H
