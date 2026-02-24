#ifndef FEISTEL_H
#define FEISTEL_H

#include "cipherinterface.h"
#include <vector>
#include <array>
#include <cstdint>

class FeistelCipher : public CipherInterface
{
public:
    FeistelCipher();

    // CipherInterface interface
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;
    virtual QString name() const override;
    virtual QString description() const override;

    // Методы для тестирования и отладки
    std::array<uint32_t, 32> getRoundKeys() const { return m_roundKeys; }
    void setKey(const QString& hexKey);

private:
    // Константы и таблицы подстановок (S-блоки) из ГОСТ Р 34.12-2015 (Приложение А.2)
    static const std::array<uint8_t, 16> PI0;
    static const std::array<uint8_t, 16> PI1;
    static const std::array<uint8_t, 16> PI2;
    static const std::array<uint8_t, 16> PI3;
    static const std::array<uint8_t, 16> PI4;
    static const std::array<uint8_t, 16> PI5;
    static const std::array<uint8_t, 16> PI6;
    static const std::array<uint8_t, 16> PI7;

    // Итерационные ключи (32 ключа по 32 бита)
    std::array<uint32_t, 32> m_roundKeys;

    // Вспомогательные функции
    uint32_t t(uint32_t value) const;
    uint32_t g(uint32_t value, uint32_t key) const;
    std::pair<uint32_t, uint32_t> G(uint32_t a1, uint32_t a0, uint32_t key) const;
    uint64_t GStar(uint32_t a1, uint32_t a0, uint32_t key) const;

    // Преобразование строк в числа и обратно
    uint32_t stringToUint32(const QString& str, int start) const;
    QString uint32ToHex(uint32_t value) const;
    uint32_t hexToUint32(const QString& hex) const;

    // Развертывание ключа
    void expandKey(const QString& key);

    // Валидация и фильтрация входных данных
    QString prepareInput(const QString& text) const;
};

// Регистратор для фабрики
class FeistelCipherRegister
{
public:
    FeistelCipherRegister();
};

#endif // FEISTEL_H
