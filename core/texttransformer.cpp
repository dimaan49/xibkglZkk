#include "TextTransformer.h"
#include <QRegularExpression>

const QVector<TextTransformer::Mapping> TextTransformer::TABLE = {
    {",", "ЗПТ"},
    {".", "ТЧК"},
    {"--", "ТТРР"},
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
    {"=", "РРВВНН"}
};

// Сортируем от длинных ключей к коротким (чтобы "--" заменился до "-")
const QVector<TextTransformer::Mapping> TextTransformer::TABLE_SORTED = []() {
    QVector<Mapping> sorted = TABLE;
    std::sort(sorted.begin(), sorted.end(),
              [](const Mapping& a, const Mapping& b) {
                  return a.symbol.length() > b.symbol.length();
              });
    return sorted;
}();

QString TextTransformer::toLetterCodes(const QString& text)
{
    QString result = text;

    // Заменяем знаки на коды (от длинных к коротким)
    for (const auto& item : TABLE_SORTED) {
        result.replace(item.symbol, item.code);
    }

    return result;
}

QString TextTransformer::fromLetterCodes(const QString& text)
{
    QString result = text;

    // Восстанавливаем знаки из кодов (ищем коды, заменяем на символы)
    for (const auto& item : TABLE) {
        result.replace(item.code, item.symbol);
    }

    return result;
}

bool TextTransformer::containsLetterCodes(const QString& text)
{
    for (const auto& item : TABLE) {
        if (text.contains(item.code)) {
            return true;
        }
    }
    return false;
}
