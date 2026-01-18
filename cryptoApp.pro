#QT -= gui
CONFIG += c++17
#CONFIG console
CONFIG -= app_bundle
QT += core widgets

TARGET = cryptoApp
TEMPLATE = app

SOURCES += \
    belazo.cpp \
    caesar.cpp \
    cardano.cpp \
    columnarcipher.cpp \
    formatter.cpp \
    logger.cpp \
    main.cpp \
    ciphercore.cpp \
    atbash.cpp \
    mainwindow.cpp \
    routecipher.cpp \
    trithemius.cpp \
    vigenere_auto.cpp \
    vigenere_ciphertext.cpp


HEADERS += \
    belazo.h \
    caesar.h \
    cardano.h \
    ciphercore.h \
    atbash.h \
    cipherinterface.h \
    columnarcipher.h \
    formatter.h \
    logger.h \
    mainwindow.h \
    routecipher.h \
    trithemius.h \
    vigenere_auto.h \
    vigenere_ciphertext.h


win32 {
    QMAKE_LFLAGS += -Wl,-subsystem,console
}

QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8
