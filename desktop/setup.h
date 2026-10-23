#pragma once
#include "process.h"
#include <QJsonObject>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QWidget>

// A page in the existing desktop window. Diagnostics and the narrowly scoped
// installed helper are subprocesses; this GUI always runs as the desktop user.
class SetupPage : public QWidget {
  Q_OBJECT
public:
  SetupPage(QString backend, QString helper, QWidget *parent = nullptr);
  void check();
  void setVaultState(bool selected, bool ready, bool pinKnown, bool configured,
                     bool busy, bool manageVault = true);
  void message(const QString &text);
  void showReport(const QJsonObject &report);
signals:
  void createVault();
  void openVault();
  void unlockVault();
  void configurePin();
  void finished();

private:
  QString backend, helper;
  QPointer<Command> job;
  QLabel *checks, *diagnostics, *result, *vaultState;
  QPushButton *refresh, *deviceRepair, *firefoxRepair, *create, *open, *unlock,
      *pin;
  bool repairDevice = false, repairFirefox = false;
  void repair(const QString &action);
  void updateRepairs();
};
