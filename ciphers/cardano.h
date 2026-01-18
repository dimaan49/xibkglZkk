#ifndef CARDANO_H
#define CARDANO_H

#include "ciphercore.h"
#include <vector>
#include <QString>

class CardanoCipher {
private:
    std::vector<std::vector<bool>> holes; // Исходная решетка
    std::vector<std::vector<QChar>> grid; // Рабочая решетка для заполнения
    int rows;
    int cols;

    // Вспомогательные методы
    QChar getAlphabetChar(int index) const;
    void clearGrid();
    int countTotalHoles() const;

    // Методы для преобразований решетки
    std::vector<std::vector<bool>> rotate180(const std::vector<std::vector<bool>>& pattern) const;
    std::vector<std::vector<bool>> mirrorX(const std::vector<std::vector<bool>>& pattern) const;
    std::vector<std::vector<bool>> mirrorY(const std::vector<std::vector<bool>>& pattern) const;
    std::vector<std::vector<bool>> getPosition(int positionNumber) const;

public:
    CardanoCipher(const std::vector<std::vector<bool>>& holePattern);

    // Основные методы
    CipherResult encrypt(const QString& text);
    CipherResult decrypt(const QString& text);

    // Информационные методы
    QString name() const;
    QString description() const;
};

#endif // CARDANO_H
