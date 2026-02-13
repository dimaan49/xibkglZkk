#ifndef PLAYFAIRCIPHER_H
#define PLAYFAIRCIPHER_H

#include "cipherinterface.h"
#include <QVector>
#include <QChar>
#include <QMap>

class PlayfairCipher : public CipherInterface
{
public:
    PlayfairCipher();

    // CipherInterface interface
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;
    virtual QString name() const override;
    virtual QString description() const override;

    // Публичные методы для использования в виджетах
    enum MatrixSize { Size5x6 = 0, Size4x8 = 1 };

    struct Position {
        int row;
        int col;
        Position(int r = -1, int c = -1) : row(r), col(c) {}
        bool isValid() const { return row >= 0 && col >= 0; }
    };

    // Генерация таблицы по лозунгу (для отображения)
    QVector<QVector<QChar>> generateTable(const QString& slogan, MatrixSize size) const;

private:
    // Константы
    static const QChar DEFAULT_FILLER;
    static const QString ALPHABET_5x6;
    static const QString ALPHABET_4x8;

    // Получение алфавита для заданного размера
    QString getAlphabet(MatrixSize size) const;

    // Нормализация символа (замена Ё, Й, Ъ)
    QChar normalizeChar(const QChar& ch, MatrixSize size) const;

    // Подготовка текста для шифрования/дешифрования
    QString prepareText(const QString& text, MatrixSize size, QChar filler, bool forEncrypt);

    // Разбивка на биграммы с обработкой повторяющихся букв
    QStringList splitIntoBigrams(const QString& text, QChar filler);

    // Создание таблицы по лозунгу
    QVector<QVector<QChar>> createTable(const QString& slogan, MatrixSize size);

    // Поиск позиции буквы в таблице
    Position findPosition(const QVector<QVector<QChar>>& table, QChar ch) const;

    // Шифрование/дешифрование биграммы
    QString processBigram(const QVector<QVector<QChar>>& table, const QString& bigram, bool encrypt);

    // Форматирование результата с пробелами между биграммами
    QString formatResult(const QStringList& bigrams);

    // Разбор зашифрованного текста с пробелами
    QStringList parseEncryptedText(const QString& text);

    // Проверка, является ли буква фиктивной и может быть удалена
    bool isFillerAndRemovable(const QString& text, int index, QChar filler) const;
};

// Регистратор
class PlayfairCipherRegister
{
public:
    PlayfairCipherRegister();
};

#endif // PLAYFAIRCIPHER_H
