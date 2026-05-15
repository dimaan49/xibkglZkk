#include "TextTransformer.h"
#include <QRegularExpression>
#include <algorithm>

// Маленькая таблица (ЗПТ, ТЧК)
const QVector<TextTransformer::Mapping> TextTransformer::SMALL_TABLE = {
    {",", "ЗПТ"},
    {".", "ТЧК"}
};

// Полная таблица
const QVector<TextTransformer::Mapping> TextTransformer::FULL_TABLE = {
    {",", "ЗЗППТТ"},
    {".", "ТТЧЧКК"},
    {"—", "ТТРР"},
    {"!", "ВВССКК"},
    {"?", "ВВППРР"},
    {":", "ДДВВТТ"},
    {";", "ТТЧЧЗЗ"},
    {"#", "РРШШТТ"},
    {"@", "ССББКК"},
    {"$", "ДДЛЛРР"},
    {"%", "ППРРЦЦ"},
    {"^", "ККННЦЦ"},
    {"&", "ММППРР"},
    {"*", "ЗЗВВДД"},
    {"(", "ППССКК"},
    {")", "ЛЛССКК"},
    {"-", "ММННСС"},
    {"+", "ППЛЛСС"},
    {"=", "РРВВНН"},
    {" ", "ППРРББ"}
};

// Статические переменные
QVector<TextTransformer::Mapping> TextTransformer::currentTable;
QVector<TextTransformer::Mapping> TextTransformer::currentTableSorted;
TextTransformer::TableType TextTransformer::currentType = TextTransformer::TABLE_FULL;

void TextTransformer::updateCurrentTable()
{
    if (currentType == TABLE_SMALL) {
        currentTable = SMALL_TABLE;
    } else {
        currentTable = FULL_TABLE;
    }

    // Сортируем от длинных к коротким
    currentTableSorted = currentTable;
    std::sort(currentTableSorted.begin(), currentTableSorted.end(),
              [](const Mapping& a, const Mapping& b) {
                  return a.symbol.length() > b.symbol.length();
              });
}

void TextTransformer::setTableType(TableType type)
{
    currentType = type;
    updateCurrentTable();
}

TextTransformer::TableType TextTransformer::getTableType()
{
    return currentType;
}

QString TextTransformer::toLetterCodes(const QString& text)
{
    if (currentTable.isEmpty()) {
        updateCurrentTable();
    }

    QString result = text;

    for (const auto& item : currentTableSorted) {
        result.replace(item.symbol, item.code);
    }

    return result;
}

QString TextTransformer::fromLetterCodes(const QString& text)
{
    if (currentTable.isEmpty()) {
        updateCurrentTable();
    }

    QString result = text;

    for (const auto& item : currentTable) {
        result.replace(item.code, item.symbol);
    }

    return result;
}

bool TextTransformer::containsLetterCodes(const QString& text)
{
    if (currentTable.isEmpty()) {
        updateCurrentTable();
    }

    for (const auto& item : currentTable) {
        if (text.contains(item.code)) {
            return true;
        }
    }
    return false;
}
