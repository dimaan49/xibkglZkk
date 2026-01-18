#QT -= gui
CONFIG += c++17
#CONFIG console
CONFIG -= app_bundle
QT += core widgets

TARGET = cryptoApp
TEMPLATE = app

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    cipherfactory.cpp \
    atbash.cpp \
    belazo.cpp \
    caesar.cpp \
    formatter.cpp \
    logger.cpp

HEADERS += \
    mainwindow.h \
    cipherinterface.h \
    cipherfactory.h \
    ciphercore.h \
    atbash.h \
    belazo.h \
    caesar.h \
    formatter.h \
    logger.h

win32 {
    QMAKE_LFLAGS += -Wl,-subsystem,console
}

QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8
