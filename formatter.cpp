#include "formatter.h"
#include <QStringBuilder>

// === Вспомогательные внутренние функции ===

namespace {
    // Получение отображаемого символа (для пробелов и т.д.)
    QString getDisplayChar(const QChar& ch) {
        if (ch.isNull()) return " ";
        if (ch == QChar(' ')) return "▯";  // специальный символ для пробела
        if (ch == QChar('\t')) return "→"; // табуляция
        if (ch == QChar('\n')) return "↵"; // новая строка
        return QString(ch);
    }

    // Получение отображаемой строки результата
    QString getDisplayString(const QString& str) {
        if (str.isEmpty()) return " ";
        if (str == " ") return "▯";
        if (str == "\t") return "→";
        if (str == "\n") return "↵";
        return str;
    }
}

// === Основные публичные методы ===

QString StepFormatter::formatResult(const CipherResult& result,
                                    bool showSteps,
                                    int groupSize,
                                    const QString& separator) {
    QString formatted;

    // Заголовок
    formatted += QStringLiteral(u"════════════════════════════════════════\n");
    formatted += QStringLiteral(u"Шифр: %1\n").arg(result.cipherName);
    formatted += QStringLiteral(u"Алфавит: %1\n").arg(result.alphabet);
    formatted += QStringLiteral(u"Длина алфавита: %1 символов\n").arg(result.alphabet.length());

    // Статистика (если есть шаги)
    if (!result.steps.isEmpty()) {
        formatted += getStatistics(result);
    }

    // Шаги преобразования (если нужно)
    if (showSteps && !result.steps.isEmpty()) {
        formatted += formatStepsTable(result.steps);
    }

    // Результат
    formatted += QStringLiteral(u"\n");
    formatted += QStringLiteral(u"Результат");

    if (groupSize > 0) {
        formatted += QStringLiteral(u" (группы по %1):\n").arg(groupSize);
        formatted += groupText(result.result, groupSize, separator);
    } else {
        formatted += QStringLiteral(u":\n");
        formatted += result.result;
    }

    formatted += QStringLiteral(u"\n════════════════════════════════════════\n");

    return formatted;
}

QString StepFormatter::formatResultOnly(const CipherResult& result,
                                        int groupSize,
                                        const QString& separator) {
    QString formatted;

    formatted += QStringLiteral(u"Шифр: %1\n").arg(result.cipherName);

    if (groupSize > 0) {
        formatted += groupText(result.result, groupSize, separator);
    } else {
        formatted += result.result;
    }

    return formatted;
}

QString StepFormatter::formatStepsOnly(const CipherResult& result) {
    if (result.steps.isEmpty()) {
        return QStringLiteral(u"Нет шагов преобразования");
    }

    QString formatted;
    formatted += QStringLiteral(u"Шифр: %1\n").arg(result.cipherName);
    formatted += formatStepsTable(result.steps);

    return formatted;
}

// === Детальные методы для UI ===

QString StepFormatter::formatStep(const CipherStep& step) {
    QString original = getDisplayChar(step.originalChar);
    QString resultChar = getDisplayString(step.resultValue);

    return QStringLiteral(u"%1: %2 → %3 (%4)")
        .arg(step.index)
        .arg(original)
        .arg(resultChar)
        .arg(step.description);
}

QString StepFormatter::formatStepsTable(const QVector<CipherStep>& steps) {
    if (steps.isEmpty()) {
        return QStringLiteral(u"\nНет шагов преобразования\n");
    }

    QString table;
    table += QStringLiteral(u"\n┌─────┬─────────┬──────────┬────────────────────────┐\n");
    table += QStringLiteral(u"│ Поз │ Исходн. │ Результат│ Описание               │\n");
    table += QStringLiteral(u"├─────┼─────────┼──────────┼────────────────────────┤\n");

    for (const auto& step : steps) {
        QString original = getDisplayChar(step.originalChar);
        QString resultChar = getDisplayString(step.resultValue);

        table += QStringLiteral(u"│ %1 │ %2 │ %3 │ %4 │\n")
            .arg(step.index, 3)
            .arg(original, 7, QChar(' '))
            .arg(resultChar, 8, QChar(' '))
            .arg(step.description.left(22), -22);
    }

    table += QStringLiteral(u"└─────┴─────────┴──────────┴────────────────────────┘\n");

    return table;
}

QString StepFormatter::formatStepsList(const QVector<CipherStep>& steps) {
    if (steps.isEmpty()) {
        return QString();
    }

    QString list;
    list = QStringLiteral(u"Шаги преобразования:\n");

    for (const auto& step : steps) {
        list += formatStep(step) + "\n";
    }

    return list;
}

// === Вспомогательные методы ===

QString StepFormatter::groupText(const QString& text,
                                 int groupSize,
                                 const QString& separator) {
    if (groupSize <= 0 || text.isEmpty()) {
        return text;
    }

    QString grouped;
    QString clean = text;

    // Убираем все пробелы для чистого группирования
    clean.replace(" ", "");

    for (int i = 0; i < clean.length(); i += groupSize) {
        if (!grouped.isEmpty()) {
            grouped += separator; // Используем переданный разделитель
        }
        grouped += clean.mid(i, groupSize);
    }

    return grouped;
}

QString StepFormatter::getStatistics(const CipherResult& result) {
    if (result.steps.isEmpty()) {
        return QString();
    }

    int totalSteps = result.steps.size();
    int inAlphabetCount = 0;
    int notInAlphabetCount = 0;

    for (const auto& step : result.steps) {
        if (step.description.contains("Не в алфавите")) {
            notInAlphabetCount++;
        } else {
            inAlphabetCount++;
        }
    }

    return QStringLiteral(u"Всего символов: %1\n")
           .arg(totalSteps) +
           QStringLiteral(u"Букв алфавита: %1\n")
           .arg(inAlphabetCount) +
           QStringLiteral(u"Других символов: %1\n")
           .arg(notInAlphabetCount);
}
