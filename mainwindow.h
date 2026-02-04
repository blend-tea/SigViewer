#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sigparser/flirtparser.h"
#include "DockManager.h"

class QLineEdit;
class QPlainTextEdit;
class QTableWidget;

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void setSigResult(const SigParser::FlirtResult &result);
    void clearSig();

private slots:
    void onFunctionSelectionChanged();
    void onSearchTextChanged(const QString &text);

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private:
    bool loadSigFile(const QString &path);
    void refreshLibraryInfo();
    void refreshFunctionsTable();
    void refreshRulesForSelection();
    void applyTableFilter();

    Ui::MainWindow *ui;
    SigParser::FlirtResult m_result;
    ads::CDockManager *m_dockManager;
    QPlainTextEdit *m_libraryInfoText;
    QLineEdit *m_searchEdit;
    QTableWidget *m_functionsTable;
    QPlainTextEdit *m_rulesText;
};

#endif // MAINWINDOW_H
