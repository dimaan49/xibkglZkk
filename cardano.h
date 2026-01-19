#ifndef CARDANO_H
#define CARDANO_H

#include "cipherinterface.h"
#include <vector>
#include <QString>

class CardanoCipher : public CipherInterface
{
public:
    CardanoCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override;
    QString description() const override;

private:
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    std::vector<std::vector<bool>> m_holes; // Решетка
    std::vector<std::vector<QChar>> m_grid; // Рабочая решетка
    int m_rows;
    int m_cols;

    // Вспомогательные методы
    QChar getAlphabetChar(int index) const;
    void clearGrid();
    int countTotalHoles() const;

    // Методы для преобразований решетки
    std::vector<std::vector<bool>> rotate180(const std::vector<std::vector<bool>>& pattern) const;
    std::vector<std::vector<bool>> mirrorX(const std::vector<std::vector<bool>>& pattern) const;
    std::vector<std::vector<bool>> mirrorY(const std::vector<std::vector<bool>>& pattern) const;
    std::vector<std::vector<bool>> getPosition(int positionNumber) const;

    // Создание решетки по умолчанию
    std::vector<std::vector<bool>> createDefaultGrid() const;
};

class CardanoCipherRegister {
public:
    CardanoCipherRegister();
};

static CardanoCipherRegister cardanoRegister;

#endif // CARDANO_H
