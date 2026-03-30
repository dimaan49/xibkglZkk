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
    ciphers/a51.cpp \
    ciphers/a52.cpp \
    ciphers/aes.cpp \
    ciphers/atbash.cpp \
    ciphers/belazo.cpp \
    ciphers/caesar.cpp \
    ciphers/cardano.cpp \
    ciphers/columntranspositioncipher.cpp \
    ciphers/ecc.cpp \
    ciphers/elgamal.cpp \
    ciphers/feistel.cpp \
    ciphers/kuznechik.cpp \
    ciphers/magma_ctr.cpp \
    ciphers/magma_ecb.cpp \
    ciphers/magmasblock16.cpp \
    ciphers/matrixcipher.cpp \
    ciphers/playfair.cpp \
    ciphers/polibiusquare.cpp \
    ciphers/routecipher.cpp \
    ciphers/rsa.cpp \
    ciphers/shannonpad.cpp \
    ciphers/trithemius.cpp \
    ciphers/vigenere_auto.cpp \
    ciphers/vigenere_ciphertext.cpp \
    classes/RestrictedSpinBox.cpp \
    core/ciphercore.cpp \
    fabrics/cipherfactory.cpp \
    fabrics/cipherwidgetfactory.cpp \
    gui/advancedsettingsdialog.cpp \
    gui/formatter.cpp \
    gui/logger.cpp \
    gui/logwindow.cpp \
    gui/mainwindow.cpp \
    gui/routecipherwidget.cpp \
    gui/stylemanager.cpp
HEADERS += $$files($$PWD/*/*.h) \    \
    ciphers/a51.h \
    ciphers/a52.h \
    ciphers/aes.h \
    ciphers/atbash.h \
    ciphers/belazo.h \
    ciphers/caesar.h \
    ciphers/cardano.h \
    ciphers/columntranspositioncipher.h \
    ciphers/ecc.h \
    ciphers/elgamal.h \
    ciphers/feistel.h \
    ciphers/kuznechik.h \
    ciphers/magma_ctr.h \
    ciphers/magma_ecb.h \
    ciphers/magmasblock16.h \
    ciphers/matrixcipher.h \
    ciphers/matrixcipherregister.h \
    ciphers/playfair.h \
    ciphers/polibiusquare.h \
    ciphers/routecipher.h \
    ciphers/rsa.h \
    ciphers/shannonpad.h \
    ciphers/trithemius.h \
    ciphers/vigenere_auto.h \
    ciphers/vigenere_ciphertext.h \
    classes/RestrictedSpinBox.h \
    core/ciphercore.h \
    core/cipherinterface.h \
    fabrics/cipherfactory.h \
    fabrics/cipherwidgetfactory.h \
    gui/advancedsettingsdialog.h \
    gui/formatter.h \
    gui/logger.h \
    gui/logwindow.h \
    gui/mainwindow.h \
    gui/routecipherwidget.h \
    gui/stylemanager.h


win32 {
    QMAKE_LFLAGS += -Wl,-subsystem,console
}

QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8
