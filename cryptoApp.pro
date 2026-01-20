#QT -= gui
CONFIG += c++17
#CONFIG console
CONFIG -= app_bundle
QT += core widgets

TARGET = cryptoApp
TEMPLATE = app

SOURCES += \
    cipherwidgetfactory.cpp \
    main.cpp \
    mainwindow.cpp \
    cipherfactory.cpp \
    atbash.cpp \
    belazo.cpp \
    cardano.cpp \
    caesar.cpp \
    stylemanager.cpp \
    trithemius.cpp \
    vigenere_auto.cpp \
    vigenere_ciphertext.cpp \
    formatter.cpp \
    logger.cpp

HEADERS += \
    cipherwidgetfactory.h \
    mainwindow.h \
    cipherinterface.h \
    cipherfactory.h \
    ciphercore.h \
    atbash.h \
    belazo.h \
    cardano.h \
    caesar.h \
    stylemanager.h \
    trithemius.h \
    vigenere_auto.h \
    vigenere_ciphertext.h \
    formatter.h \
    logger.h

win32 {
    QMAKE_LFLAGS += -Wl,-subsystem,console
}

QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8
