#ifndef FORMATTER_H
#define FORMATTER_H

#include "ciphercore.h"
#include <QString>

class StepFormatter {
public:
    // Единственный основной метод с разделителем
    static QString formatResult(const CipherResult& result,
                                bool showSteps = false,
                                int groupSize = 0,
                                const QString& separator = QString(" "));

    // Только результат с разделителем
    static QString formatResultOnly(const CipherResult& result,
                                    int groupSize = 0,
                                    const QString& separator = QString(" "));

    // Только шаги
    static QString formatStepsOnly(const CipherResult& result);

    // Детальные методы для UI
    static QString formatStep(const CipherStep& step);
    static QString formatStepsTable(const QVector<CipherStep>& steps);
    static QString formatStepsList(const QVector<CipherStep>& steps);

    // Вспомогательные методы
    static QString groupText(const QString& text,
                             int groupSize,
                             const QString& separator = QString(" "));
    static QString getStatistics(const CipherResult& result);
};

#endif // FORMATTER_H
