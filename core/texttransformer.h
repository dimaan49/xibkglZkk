#ifndef TEXTTRANSFORMER_H
#define TEXTTRANSFORMER_H

#include <QString>
#include <QVector>

class TextTransformer
{
public:
    enum TableType {
        TABLE_SMALL,   // ЗПТ, ТЧК
        TABLE_FULL     // ЗЗППТТ, ТТЧЧКК и т.д.
    };

    static void setTableType(TableType type);
    static TableType getTableType();

    static QString toLetterCodes(const QString& text);
    static QString fromLetterCodes(const QString& text);
    static bool containsLetterCodes(const QString& text);

private:
    struct Mapping {
        QString symbol;
        QString code;
    };

    static const QVector<Mapping> SMALL_TABLE;
    static const QVector<Mapping> FULL_TABLE;

    static QVector<Mapping> currentTable;
    static QVector<Mapping> currentTableSorted;
    static TableType currentType;

    static void updateCurrentTable();
};

#endif // TEXTTRANSFORMER_H
