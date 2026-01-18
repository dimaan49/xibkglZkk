#ifndef COLUMNARCIPHER_H
#define COLUMNARCIPHER_H

#include "ciphercore.h"
#include "routecipher.h"
#include <QString>
#include <QVector>

class ColumnarCipher {
private:
    RouteCipher routeCipher;
    int rows;
    int cols;

    // Преобразование ключевого слова в порядок столбцов
    QVector<int> keyToColumnOrder(const QString& key) const;

    // Создание конфигурации для RouteCipher
    RouteCipherConfig createConfig(const QString& key,
                                  const QVector<Direction>& writeDirections,
                                  const QVector<Direction>& readDirections) const;

public:
    ColumnarCipher(int rows = 0, int cols = 0);

    // ПРОСТОЙ интерфейс: только текст и ключ (все строки слева направо, все столбцы сверху вниз)
    CipherResult encrypt(const QString& text, const QString& key);

    // ПОЛНЫЙ интерфейс: можно задать все параметры
    CipherResult encrypt(const QString& text, const QString& key,
                        const QVector<Direction>& writeDirections,
                        const QVector<Direction>& readDirections = QVector<Direction>(),
                        int rows = 0, int cols = 0);

    // Дешифрование
    CipherResult decrypt(const QString& text, const QString& key);
    CipherResult decrypt(const QString& text, const QString& key,
                        const QVector<Direction>& writeDirections,
                        const QVector<Direction>& readDirections = QVector<Direction>(),
                        int rows = 0, int cols = 0);

    // Установка размера таблицы
    void setTableSize(int rows, int cols);

    QString name() const;
    QString description() const;
};

#endif // COLUMNARCIPHER_H
