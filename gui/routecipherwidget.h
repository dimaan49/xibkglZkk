#ifndef ROUTECIPHERADVANCEDWIDGET_H
#define ROUTECIPHERADVANCEDWIDGET_H

#include <QWidget>
#include <QSpinBox>
#include <QComboBox>
#include <QTableWidget>
#include <QPushButton>
#include <QGroupBox>
#include <QCheckBox>
#include <QLabel>
#include <QTabWidget>
#include <QListWidget>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QVector>
#include "routecipher.h"

class RouteCipherAdvancedWidget : public QWidget
{
    Q_OBJECT

public:
    explicit RouteCipherAdvancedWidget(QWidget *parent = nullptr);
    ~RouteCipherAdvancedWidget();

    // Геттеры для фабрики - получение параметров
    int getRows() const;
    int getCols() const;
    QVector<Direction> getWriteDirections() const;
    QVector<Direction> getReadDirections() const;
    QVector<int> getRowOrder() const;
    QVector<int> getColumnOrder() const;

    // Сеттеры для фабрики - установка параметров
    void setRows(int rows);
    void setCols(int cols);
    void setWriteDirections(const QVector<Direction>& dirs);
    void setReadDirections(const QVector<Direction>& dirs);
    void setRowOrder(const QVector<int>& order);
    void setColumnOrder(const QVector<int>& order);
    QVariantMap getParameters() const;

    // Валидация параметров
    bool validate(QString& errorMessage) const;

    // Сброс к значениям по умолчанию
    void resetToDefault();

signals:
    void parametersChanged();

private slots:
    void onRowsChanged(int value);
    void onColsChanged(int value);
    void onAutoSizeToggled(bool checked);
    void onFillExample();
    void onRandomizeAll();
    void onResetToDefault();
    void onWriteDirectionChanged(int index);
    void onReadDirectionChanged(int index);
    void onZigzagClicked();
    void onAllWriteLeftClicked();
    void onAllWriteRightClicked();
    void onAllReadTopClicked();
    void onAllReadBottomClicked();
    void onRowOrderNormalize();
    void onRowOrderReverse();
    void onColumnOrderNormalize();
    void onColumnOrderReverse();
    void onTabChanged(int index);
    void onRowListChanged();
    void onColumnListChanged();
public slots:
    // ... существующие слоты ...
    void onRowSpinChanged(int value);
    void onColSpinChanged(int value);
    void setPreviewText(const QString& text);
    void updateAutoSizeDisplay(int textLength);

private:
    void setupUI();
    void createSizeControls();
    void createDirectionControls();
    void createOrderControls();
    void createTablePreview();
    void updateTablePreview();
    void updateDirectionControlsState();
    void updateOrderControlsState();
    void syncDirectionsFromTable();
    void syncOrdersFromLists();
    void updateRowOrderSpins();
    void updateColumnOrderSpins();
    QString directionToString(Direction dir, bool isWrite) const;

    // Размеры таблицы
    QCheckBox* m_autoSizeCheck;
    QSpinBox* m_rowsSpin;
    QSpinBox* m_colsSpin;
    QLabel* m_sizeInfoLabel;
    int m_currentRows;
    int m_currentCols;
    bool m_updating;

    // Вкладки
    QTabWidget* m_tabWidget;

    // === Вкладка 1: Направления ===
    QWidget* m_directionsTab;

    // Группа направлений записи (по строкам)
    QGroupBox* m_writeGroup;
    QVector<QComboBox*> m_writeDirectionCombos;
    QPushButton* m_zigzagBtn;
    QPushButton* m_allWriteLeftBtn;
    QPushButton* m_allWriteRightBtn;
    QGridLayout* m_writeGrid;

    // Группа направлений чтения (по столбцам)
    QGroupBox* m_readGroup;
    QVector<QComboBox*> m_readDirectionCombos;
    QPushButton* m_allReadTopBtn;
    QPushButton* m_allReadBottomBtn;
    QGridLayout* m_readGrid;

    // === Вкладка 2: Порядок ===
    QWidget* m_orderTab;

    // Порядок строк (drag & drop список)
    QGroupBox* m_rowOrderGroup;
    QListWidget* m_rowOrderList;
    QPushButton* m_rowOrderNormalizeBtn;
    QPushButton* m_rowOrderReverseBtn;

    // Порядок столбцов (drag & drop список)
    QGroupBox* m_colOrderGroup;
    QListWidget* m_colOrderList;
    QPushButton* m_colOrderNormalizeBtn;
    QPushButton* m_colOrderReverseBtn;

    // Дополнительные спинбоксы для точного ввода порядка
    QVector<QSpinBox*> m_rowOrderSpins;
    QVector<QSpinBox*> m_colOrderSpins;
    QWidget* m_rowOrderSpinsWidget;
    QWidget* m_colOrderSpinsWidget;

    // === Вкладка 3: Предпросмотр ===
    QWidget* m_previewTab;
    QTableWidget* m_previewTable;
    QLabel* m_writePathLabel;
    QLabel* m_readPathLabel;
    QLabel* m_tableInfoLabel;

    // === Нижняя панель с кнопками ===
    QPushButton* m_fillExampleBtn;
    QPushButton* m_randomizeAllBtn;
    QPushButton* m_resetBtn;

    QString m_previewText;

    // Константы
    static const int MAX_VISIBLE_ROWS = 100;
    static const int MAX_VISIBLE_COLS = 100;
    static const int PREVIEW_MAX_SIZE = 100;
};

#endif // ROUTECIPHERADVANCEDWIDGET_H
