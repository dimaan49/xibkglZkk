#include "analysiswindow.h"
#include "qcustomplot.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QFileDialog>
#include <QTextStream>
#include <QDateTime>
#include <QTabWidget>
#include <QTableView>
#include <QPushButton>
#include <QStandardItemModel>

AnalysisWindow::AnalysisWindow(QWidget* parent)
    : QDialog(parent)
    , m_tabWidget(nullptr)
    , m_histogramView(nullptr)
    , m_frequencyTableView(nullptr)
    , m_refreshButton(nullptr)
    , m_exportButton(nullptr)
    , m_copyButton(nullptr)
    , m_originalTotal(0)
    , m_encryptedTotal(0)
    , m_tableModel(nullptr)
    , m_histogramModeGroup(nullptr)
    , m_currentHistogramMode(1)
{
    setupUI();
    setWindowTitle("Анализ шифров");
    resize(1000, 650);
}

AnalysisWindow::~AnalysisWindow() {}

void AnalysisWindow::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    // Кнопки
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    m_refreshButton = new QPushButton("Обновить");
    m_exportButton = new QPushButton("Экспорт CSV");
    m_copyButton = new QPushButton("Копировать");

    m_refreshButton->setMinimumHeight(30);
    m_exportButton->setMinimumHeight(30);
    m_copyButton->setMinimumHeight(30);

    connect(m_refreshButton, &QPushButton::clicked, this, &AnalysisWindow::onRefresh);
    connect(m_exportButton, &QPushButton::clicked, this, &AnalysisWindow::onExportData);
    connect(m_copyButton, &QPushButton::clicked, this, &AnalysisWindow::onCopyToClipboard);

    buttonLayout->addWidget(m_refreshButton);
    buttonLayout->addWidget(m_exportButton);
    buttonLayout->addWidget(m_copyButton);
    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Вкладки
    m_tabWidget = new QTabWidget();


    QWidget* histTab = new QWidget();
    QVBoxLayout* histLayout = new QVBoxLayout(histTab);

    // Кнопки переключения режима гистограммы
    QHBoxLayout* modeLayout = new QHBoxLayout();
    modeLayout->setSpacing(5);

    QPushButton* btnOriginal = new QPushButton("Исходный текст");
    btnOriginal->setCheckable(true);
    QPushButton* btnEncrypted = new QPushButton("Шифртекст");
    btnEncrypted->setCheckable(true);
    QPushButton* btnCompare = new QPushButton("Сравнение");
    btnCompare->setCheckable(true);

    m_histogramModeGroup = new QButtonGroup(this);
    m_histogramModeGroup->addButton(btnOriginal, 0);
    m_histogramModeGroup->addButton(btnEncrypted, 1);
    m_histogramModeGroup->addButton(btnCompare, 2);
    connect(m_histogramModeGroup, QOverload<int>::of(&QButtonGroup::idClicked),
            this, &AnalysisWindow::onHistogramModeChanged);

    modeLayout->addWidget(btnOriginal);
    modeLayout->addWidget(btnEncrypted);
    modeLayout->addWidget(btnCompare);
    modeLayout->addStretch();

    histLayout->addLayout(modeLayout);

    m_histogramView = new QCustomPlot();
    m_histogramView->setMinimumHeight(400);
    histLayout->addWidget(m_histogramView);
    m_tabWidget->addTab(histTab, "Гистограмма");

    // Установить режим по умолчанию (шифртекст)
    btnEncrypted->setChecked(true);
    m_currentHistogramMode = 1;

    // Таблица
    QWidget* tableTab = new QWidget();
    QVBoxLayout* tableLayout = new QVBoxLayout(tableTab);
    m_frequencyTableView = new QTableView();
    m_frequencyTableView->setAlternatingRowColors(true);
    m_frequencyTableView->horizontalHeader()->setStretchLastSection(true);
    tableLayout->addWidget(m_frequencyTableView);
    m_tabWidget->addTab(tableTab, "Частотная таблица");

    mainLayout->addWidget(m_tabWidget);

    // Модель таблицы
    m_tableModel = new QStandardItemModel(this);
    m_tableModel->setHorizontalHeaderLabels(QStringList()
        << "Буква" << "Исх" << "%" << "Шифр" << "%" << "Разн" << "%");
    m_frequencyTableView->setModel(m_tableModel);
}

void AnalysisWindow::setTexts(const QString& original, const QString& encrypted)
{
    m_originalText = original;
    m_encryptedText = encrypted;
    updateAnalysis();
}

QString AnalysisWindow::getRussianAlphabet() const
{
    return "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
}

void AnalysisWindow::calculateFrequency(const QString& text, QMap<QChar, int>& freq, int& total)
{
    freq.clear();
    total = 0;

    QString alphabet = getRussianAlphabet();
    QString upperText = text.toUpper();

    for (QChar ch : alphabet) freq[ch] = 0;
    for (QChar ch : upperText) {
        if (freq.contains(ch)) {
            freq[ch]++;
            total++;
        }
    }
}

void AnalysisWindow::createHistogram()
{
    if (!m_histogramView) return;
    m_histogramView->clearPlottables();

    QVector<double> ticks;
    QVector<QString> labels;
    QString alphabet = getRussianAlphabet();

    for (int i = 0; i < alphabet.length(); ++i) {
        ticks << i + 1.0;
        labels << QString(alphabet[i]);
    }

    QCPBars* bars = nullptr;

    if (m_currentHistogramMode == 0) {  // Исходный текст
        QVector<double> data;
        for (QChar ch : alphabet) {
            double percent = m_originalTotal > 0 ? (m_originalFreq.value(ch, 0) * 100.0 / m_originalTotal) : 0.0;
            data << percent;
        }
        bars = new QCPBars(m_histogramView->xAxis, m_histogramView->yAxis);
        bars->setName("Исходный текст");
        bars->setPen(QPen(QColor(0, 120, 200).lighter(130)));
        bars->setBrush(QColor(0, 120, 200, 180));
        bars->setData(ticks, data);
        bars->setWidth(0.6);
        m_histogramView->xAxis->setRange(0.5, ticks.size() + 0.5);

    } else if (m_currentHistogramMode == 1) {  // Шифртекст
        QVector<double> data;
        for (QChar ch : alphabet) {
            double percent = m_encryptedTotal > 0 ? (m_encryptedFreq.value(ch, 0) * 100.0 / m_encryptedTotal) : 0.0;
            data << percent;
        }
        bars = new QCPBars(m_histogramView->xAxis, m_histogramView->yAxis);
        bars->setName("Шифртекст");
        bars->setPen(QPen(QColor(200, 80, 0).lighter(130)));
        bars->setBrush(QColor(200, 80, 0, 180));
        bars->setData(ticks, data);
        bars->setWidth(0.6);
        m_histogramView->xAxis->setRange(0.5, ticks.size() + 0.5);

    } else {  // Сравнение
        QVector<double> origData, encData, ticksEnc;
        for (QChar ch : alphabet) {
            double origPercent = m_originalTotal > 0 ? (m_originalFreq.value(ch, 0) * 100.0 / m_originalTotal) : 0.0;
            double encPercent = m_encryptedTotal > 0 ? (m_encryptedFreq.value(ch, 0) * 100.0 / m_encryptedTotal) : 0.0;
            origData << origPercent;
            encData << encPercent;
            ticksEnc << ticks[origData.size() - 1] + 0.35;
        }

        QCPBars* origBars = new QCPBars(m_histogramView->xAxis, m_histogramView->yAxis);
        origBars->setName("Исходный текст");
        origBars->setPen(QPen(QColor(0, 120, 200).lighter(130)));
        origBars->setBrush(QColor(0, 120, 200, 180));
        origBars->setData(ticks, origData);
        origBars->setWidth(0.35);

        QCPBars* encBars = new QCPBars(m_histogramView->xAxis, m_histogramView->yAxis);
        encBars->setName("Шифртекст");
        encBars->setPen(QPen(QColor(200, 80, 0).lighter(130)));
        encBars->setBrush(QColor(200, 80, 0, 180));
        encBars->setData(ticksEnc, encData);
        encBars->setWidth(0.35);

        m_histogramView->xAxis->setRange(0.5, ticks.size() + 1);
    }

    // Настройка оси X
    QSharedPointer<QCPAxisTickerText> ticker(new QCPAxisTickerText);
    ticker->addTicks(ticks, labels);
    m_histogramView->xAxis->setTicker(ticker);
    m_histogramView->xAxis->setTickLabelRotation(60);
    m_histogramView->xAxis->setSubTicks(false);
    m_histogramView->xAxis->setLabel("Буквы");

    // Настройка оси Y
    m_histogramView->yAxis->setLabel("Частота (%)");
    m_histogramView->yAxis->setRange(0, 100);

    // Легенда
    m_histogramView->legend->setVisible(true);
    m_histogramView->legend->setBrush(QBrush(QColor(255, 255, 255, 230)));
    m_histogramView->axisRect()->insetLayout()->setInsetAlignment(0, Qt::AlignTop | Qt::AlignRight);

    m_histogramView->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom);
    m_histogramView->replot();
}

void AnalysisWindow::createFrequencyTable()
{
    if (!m_tableModel) return;
    m_tableModel->removeRows(0, m_tableModel->rowCount());

    QString alphabet = getRussianAlphabet();
    for (QChar ch : alphabet) {
        int origCount = m_originalFreq.value(ch, 0);
        int encCount = m_encryptedFreq.value(ch, 0);
        double origPercent = m_originalTotal > 0 ? (origCount * 100.0 / m_originalTotal) : 0.0;
        double encPercent = m_encryptedTotal > 0 ? (encCount * 100.0 / m_encryptedTotal) : 0.0;

        QList<QStandardItem*> items;
        items << new QStandardItem(QString(ch));
        items << new QStandardItem(QString::number(origCount));
        items << new QStandardItem(QString::number(origPercent, 'f', 2) + "%");
        items << new QStandardItem(QString::number(encCount));
        items << new QStandardItem(QString::number(encPercent, 'f', 2) + "%");
        items << new QStandardItem(QString::number(encCount - origCount));
        items << new QStandardItem(QString::number(encPercent - origPercent, 'f', 2) + "%");

        for (auto* item : items) item->setTextAlignment(Qt::AlignCenter);
        m_tableModel->appendRow(items);
    }
    m_frequencyTableView->resizeColumnsToContents();
}

void AnalysisWindow::updateAnalysis()
{
    calculateFrequency(m_originalText, m_originalFreq, m_originalTotal);
    calculateFrequency(m_encryptedText, m_encryptedFreq, m_encryptedTotal);
    createHistogram();
    createFrequencyTable();
}

void AnalysisWindow::onRefresh() { updateAnalysis(); }

void AnalysisWindow::onExportData()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Сохранить", "analysis.csv", "CSV (*.csv)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) return;

    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);
    out << "Буква;Исходный;%;Шифртекст;%;Разница\n";

    QString alphabet = getRussianAlphabet();
    for (QChar ch : alphabet) {
        int origCount = m_originalFreq.value(ch, 0);
        int encCount = m_encryptedFreq.value(ch, 0);
        double origPercent = m_originalTotal > 0 ? (origCount * 100.0 / m_originalTotal) : 0.0;
        double encPercent = m_encryptedTotal > 0 ? (encCount * 100.0 / m_encryptedTotal) : 0.0;

        out << QString(ch) << ";"
            << origCount << ";"
            << QString::number(origPercent, 'f', 2) << "%;"
            << encCount << ";"
            << QString::number(encPercent, 'f', 2) << "%;"
            << (encCount - origCount) << "\n";
    }
    file.close();
    QMessageBox::information(this, "Готово", "Данные сохранены");
}

void AnalysisWindow::onCopyToClipboard()
{
    if (!m_tableModel) return;
    QString text;
    for (int col = 0; col < m_tableModel->columnCount(); ++col)
        text += (col ? "\t" : "") + m_tableModel->horizontalHeaderItem(col)->text();
    text += "\n";
    for (int row = 0; row < m_tableModel->rowCount(); ++row) {
        for (int col = 0; col < m_tableModel->columnCount(); ++col)
            text += (col ? "\t" : "") + m_tableModel->item(row, col)->text();
        text += "\n";
    }
    QApplication::clipboard()->setText(text);
    QMessageBox::information(this, "Готово", "Таблица скопирована");
}

void AnalysisWindow::onHistogramModeChanged(int mode)
{
    m_currentHistogramMode = mode;
    createHistogram();
}
