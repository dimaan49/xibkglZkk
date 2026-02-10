#QT -= gui
CONFIG += c++17
#CONFIG console
CONFIG -= app_bundle
QT += core widgets

TARGET = cryptoApp
TEMPLATE = app

INCLUDEPATH += \
    $$PWD \
    $$PWD\core \
    $$PWD\gui \
    $$PWD\ciphers \
    $$PWD\fabrics \
    $$PWD\classes




SOURCES += main.cpp $$files($$PWD/*/*.cpp) \
    ciphers/atbash.cpp \
    ciphers/belazo.cpp \
    ciphers/caesar.cpp \
    ciphers/cardano.cpp \
    ciphers/magmasblock.cpp \
    ciphers/matrixcipher.cpp \
    ciphers/polibiusquare.cpp \
    ciphers/routecipher.cpp \
    ciphers/trithemius.cpp \
    ciphers/vigenere_auto.cpp \
    ciphers/vigenere_ciphertext.cpp \
    classes/RestrictedSpinBox.cpp \
    core/ciphercore.cpp \
    fabrics/cipherfactory.cpp \
    fabrics/cipherwidgetfactory.cpp \
    gui/formatter.cpp \
    gui/logger.cpp \
    gui/logwindow.cpp \
    gui/mainwindow.cpp \
    gui/stylemanager.cpp
HEADERS += $$files($$PWD/*/*.h) \    \
    ciphers/atbash.h \
    ciphers/belazo.h \
    ciphers/caesar.h \
    ciphers/cardano.h \
    ciphers/magmasblock.h \
    ciphers/matrixcipher.h \
    ciphers/matrixcipherregister.h \
    ciphers/polibiusquare.h \
    ciphers/routecipher.h \
    ciphers/trithemius.h \
    ciphers/vigenere_auto.h \
    ciphers/vigenere_ciphertext.h \
    classes/RestrictedSpinBox.h \
    core/ciphercore.h \
    core/cipherinterface.h \
    fabrics/cipherfactory.h \
    fabrics/cipherwidgetfactory.h \
    gui/formatter.h \
    gui/logger.h \
    gui/logwindow.h \
    gui/mainwindow.h \
    gui/stylemanager.h


win32 {
    QMAKE_LFLAGS += -Wl,-subsystem,console
}

QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8
