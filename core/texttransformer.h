#ifndef TEXTTRANSFORMER_H
#define TEXTTRANSFORMER_H

#include <QString>
#include <QVector>

class TextTransformer
{
public:
    // Заменяет знаки препинания на буквенные коды
    static QString toLetterCodes(const QString& text);

    // Восстанавливает знаки препинания из буквенных кодов
    static QString fromLetterCodes(const QString& text);

    // Проверяет, содержит ли текст буквенные коды
    static bool containsLetterCodes(const QString& text);

private:
    struct Mapping {
        QString symbol;  // знак (",", ".", "--" и т.д.)
        QString code;    // буквенный код ("ЗЗППТТ", "ТТЧЧКК")
    };

    static const QVector<Mapping> TABLE;
    static const QVector<Mapping> TABLE_SORTED; // для замены от длинных к коротким
};

#endif // TEXTTRANSFORMER_H
