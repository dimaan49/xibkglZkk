#ifndef ATBASH_H
#define ATBASH_H

#include "ciphercore.h"

class AtbashCipher {
private:
    QString alphabet;

public:
    AtbashCipher();

    CipherResult encrypt(const QString& text) const;
    CipherResult decrypt(const QString& text) const;

    QString name() const;
    QString description() const;
};

#endif // ATBASH_H
