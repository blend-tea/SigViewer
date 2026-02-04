#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QLineEdit>
#include <QMessageBox>
#include <QMimeData>
#include <QUrl>
#include <QGroupBox>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setAcceptDrops(true);

    m_dockManager = new ads::CDockManager(this);

    // Library info dock
    QWidget *libWidget = new QWidget();
    QVBoxLayout *libLayout = new QVBoxLayout(libWidget);
    libLayout->setContentsMargins(0, 0, 0, 0);
    QGroupBox *libGroup = new QGroupBox(tr("Library info"));
    QVBoxLayout *libGroupLayout = new QVBoxLayout(libGroup);
    m_libraryInfoText = new QPlainTextEdit();
    m_libraryInfoText->setReadOnly(true);
    m_libraryInfoText->setPlaceholderText(tr("Drop .sig file here"));
    m_libraryInfoText->setMaximumHeight(120);
    libGroupLayout->addWidget(m_libraryInfoText);
    libLayout->addWidget(libGroup);
    ads::CDockWidget *libraryDock = m_dockManager->createDockWidget(tr("Library info"));
    libraryDock->setWidget(libWidget);
    auto *leftArea = m_dockManager->addDockWidget(ads::LeftDockWidgetArea, libraryDock);
    ui->menuView->addAction(libraryDock->toggleViewAction());

    // Functions dock
    QWidget *funcWidget = new QWidget();
    QVBoxLayout *funcLayout = new QVBoxLayout(funcWidget);
    funcLayout->setContentsMargins(0, 0, 0, 0);
    QGroupBox *funcGroup = new QGroupBox(tr("Functions"));
    QVBoxLayout *funcGroupLayout = new QVBoxLayout(funcGroup);
    m_searchEdit = new QLineEdit();
    m_searchEdit->setPlaceholderText(tr("Search..."));
    m_searchEdit->setClearButtonEnabled(true);
    funcGroupLayout->addWidget(m_searchEdit);
    m_functionsTable = new QTableWidget();
    m_functionsTable->setColumnCount(6);
    m_functionsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_functionsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_functionsTable->setHorizontalHeaderLabels({ tr("Module"), tr("Name"), tr("Offset"), tr("Local"), tr("Collision"), tr("Signature") });
    m_functionsTable->horizontalHeader()->setStretchLastSection(true);
    m_functionsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    funcGroupLayout->addWidget(m_functionsTable);
    funcLayout->addWidget(funcGroup);
    ads::CDockWidget *functionsDock = m_dockManager->createDockWidget(tr("Functions"));
    functionsDock->setWidget(funcWidget);
    m_dockManager->addDockWidget(ads::BottomDockWidgetArea, functionsDock, leftArea);
    ui->menuView->addAction(functionsDock->toggleViewAction());
    connect(m_functionsTable->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &MainWindow::onFunctionSelectionChanged);
    connect(m_searchEdit, &QLineEdit::textChanged, this, &MainWindow::onSearchTextChanged);

    // Detection rules dock
    QWidget *rulesWidget = new QWidget();
    QVBoxLayout *rulesLayout = new QVBoxLayout(rulesWidget);
    rulesLayout->setContentsMargins(0, 0, 0, 0);
    QGroupBox *rulesGroup = new QGroupBox(tr("Detection rules"));
    QVBoxLayout *rulesGroupLayout = new QVBoxLayout(rulesGroup);
    m_rulesText = new QPlainTextEdit();
    m_rulesText->setReadOnly(true);
    m_rulesText->setPlaceholderText(tr("Select a function or module to view rules"));
    rulesGroupLayout->addWidget(m_rulesText);
    rulesLayout->addWidget(rulesGroup);
    ads::CDockWidget *rulesDock = m_dockManager->createDockWidget(tr("Detection rules"));
    rulesDock->setWidget(rulesWidget);
    m_dockManager->addDockWidget(ads::RightDockWidgetArea, rulesDock);
    ui->menuView->addAction(rulesDock->toggleViewAction());
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setSigResult(const SigParser::FlirtResult &result)
{
    m_result = result;
    refreshLibraryInfo();
    refreshFunctionsTable();
    refreshRulesForSelection();
}

void MainWindow::clearSig()
{
    m_result = SigParser::FlirtResult();
    m_result.success = false;
    refreshLibraryInfo();
    refreshFunctionsTable();
    refreshRulesForSelection();
}

void MainWindow::refreshLibraryInfo()
{
    if (!m_result.success) {
        m_libraryInfoText->setPlainText(QString());
        m_libraryInfoText->setPlaceholderText("Drop .sig file here");
        return;
    }
    m_libraryInfoText->setPlaceholderText(QString());
    QStringList lines;
    lines << "Library: " + m_result.libraryName;
    lines << "Version: " + QString::number(m_result.header.version);
    lines << "Arch: " + SigParser::archToString(m_result.header.arch);
    lines << "File types: " + SigParser::fileTypesToString(m_result.header.fileTypes);
    lines << "OS types: " + SigParser::osTypesToString(m_result.header.osTypes);
    lines << "App types: " + SigParser::appTypesToString(m_result.header.appTypes);
    lines << "Features: " + SigParser::featuresToString(m_result.header.features);
    lines << "Modules: " + QString::number(m_result.modules.size());
    m_libraryInfoText->setPlainText(lines.join("\n"));
}

void MainWindow::refreshFunctionsTable()
{
    QTableWidget *t = m_functionsTable;
    t->setRowCount(0);
    if (!m_result.success) return;
    QVector<SigParser::FlirtResult::FunctionEntry> entries = m_result.allFunctions();
    t->setRowCount(entries.size());
    for (int row = 0; row < entries.size(); ++row) {
        const auto &e = entries[row];
        t->setItem(row, 0, new QTableWidgetItem(QString::number(e.moduleIndex)));
        t->setItem(row, 1, new QTableWidgetItem(e.function->name));
        t->setItem(row, 2, new QTableWidgetItem(QString("0x%1").arg(e.function->offset, 0, 16)));
        t->setItem(row, 3, new QTableWidgetItem(e.function->isLocal ? "Y" : ""));
        t->setItem(row, 4, new QTableWidgetItem(e.function->isCollision ? "!" : ""));
        t->setItem(row, 5, new QTableWidgetItem(e.module->patternPathHex()));
    }
    applyTableFilter();
}

void MainWindow::applyTableFilter()
{
    const QString text = m_searchEdit->text().trimmed();
    QTableWidget *t = m_functionsTable;
    for (int row = 0; row < t->rowCount(); ++row) {
        if (text.isEmpty()) {
            t->setRowHidden(row, false);
            continue;
        }
        bool match = false;
        for (int col = 0; col < t->columnCount(); ++col) {
            QTableWidgetItem *item = t->item(row, col);
            if (item && item->text().contains(text, Qt::CaseInsensitive)) {
                match = true;
                break;
            }
        }
        t->setRowHidden(row, !match);
    }
}

void MainWindow::onSearchTextChanged(const QString &)
{
    applyTableFilter();
}

void MainWindow::refreshRulesForSelection()
{
    int row = m_functionsTable->currentRow();
    if (row < 0 || !m_result.success || row >= m_result.allFunctions().size()) {
        m_rulesText->setPlainText(QString());
        m_rulesText->setPlaceholderText("Select a function or module to view rules");
        return;
    }
    m_rulesText->setPlaceholderText(QString());
    QVector<SigParser::FlirtResult::FunctionEntry> entries = m_result.allFunctions();
    const auto &e = entries[row];
    QStringList lines;
    lines << "Pattern path: " + e.module->patternPathHex();
    lines << e.module->rulesSummary();
    m_rulesText->setPlainText(lines.join("\n\n"));
}

void MainWindow::onFunctionSelectionChanged()
{
    refreshRulesForSelection();
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        const QList<QUrl> urls = event->mimeData()->urls();
        if (!urls.isEmpty()) {
            QString path = urls.first().toLocalFile();
            if (path.endsWith(".sig", Qt::CaseInsensitive) || path.endsWith(".sig.gz", Qt::CaseInsensitive))
                event->acceptProposedAction();
        }
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    const QList<QUrl> urls = event->mimeData()->urls();
    if (urls.isEmpty()) return;
    QString path = urls.first().toLocalFile();
    if (path.endsWith(".sig", Qt::CaseInsensitive) || path.endsWith(".sig.gz", Qt::CaseInsensitive)) {
        event->acceptProposedAction();
        if (loadSigFile(path))
            statusBar()->showMessage("Loaded: " + path, 3000);
        else
            statusBar()->showMessage("Failed to load: " + path, 5000);
    }
}

bool MainWindow::loadSigFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "SigViewer", "Cannot open file: " + path);
        return false;
    }
    QByteArray data = f.readAll();
    f.close();
    if (path.endsWith(".sig.gz", Qt::CaseInsensitive)) {
        data = SigParser::FlirtParser::decompressGzip(data);
        if (data.isEmpty()) {
            QMessageBox::warning(this, "SigViewer", "Failed to decompress .sig.gz file.");
            return false;
        }
    }
    SigParser::FlirtParser parser;
    SigParser::FlirtResult result = parser.parse(data);
    if (!result.success) {
        QMessageBox::warning(this, "SigViewer", "Parse error: " + result.errorMessage);
        clearSig();
        return false;
    }
    setSigResult(result);
    return true;
}
