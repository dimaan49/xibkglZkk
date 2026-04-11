#ifndef ANALYSISWINDOW_H
#define ANALYSISWINDOW_H

#include <QDialog>
#include <QMap>
#include <QVector>
#include <QButtonGroup>

class QTabWidget;
class QTableView;
class QPushButton;
class QStandardItemModel;
class QCustomPlot;

class AnalysisWindow : public QDialog
{
    Q_OBJECT

public:
    explicit AnalysisWindow(QWidget* parent = nullptr);
    ~AnalysisWindow();
    void setTexts(const QString& original, const QString& encrypted);

private slots:
    void onRefresh();
    void onExportData();
    void onCopyToClipboard();
    void onHistogramModeChanged(int mode);

private:
    void setupUI();
    void updateAnalysis();
    void calculateFrequency(const QString& text, QMap<QChar, int>& freq, int& total);
    void createHistogram();
    void createFrequencyTable();
    QString getRussianAlphabet() const;

    QTabWidget* m_tabWidget;
    QCustomPlot* m_histogramView;
    QTableView* m_frequencyTableView;
    QPushButton* m_refreshButton;
    QPushButton* m_exportButton;
    QPushButton* m_copyButton;
    QButtonGroup* m_histogramModeGroup;
    int m_currentHistogramMode;  // 0 - исходный, 1 - шифртекст, 2 - сравнени

    QString m_originalText;
    QString m_encryptedText;

    QMap<QChar, int> m_originalFreq;
    QMap<QChar, int> m_encryptedFreq;
    int m_originalTotal;
    int m_encryptedTotal;

    QStandardItemModel* m_tableModel;
};

#endif
