#pragma once
#include "process.h"
#include <QJsonArray>
#include <QPointer>
#include <QSet>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QStandardItemModel;
class QSortFilterProxyModel;
class QTableView;

class CredentialsPage : public QWidget {
  Q_OBJECT
public:
  explicit CredentialsPage(QString backend, QWidget *parent = nullptr);
  void setContext(const QString &socket, bool unlocked,
                  const QString &revision);
signals:
  void unlockRequested();

protected:
  void showEvent(QShowEvent *event) override;
  void hideEvent(QHideEvent *event) override;

private:
  QString backend, socket, revision;
  bool unlocked = false;
  quint64 generation = 0;
  int total = -1;
  QJsonArray staged;
  QSet<QString> ids;
  QPointer<Command> command;
  QLabel *message, *details;
  QLineEdit *search;
  QPushButton *refresh, *unlock;
  QTableView *table;
  QStandardItemModel *model;
  QSortFilterProxyModel *filter;
  void clear();
  void updateAvailability();
  void reload();
  void readPage(int offset);
  void failed(const QString &text);
  void populate();
  void updateCount();
  void updateDetails();
};
