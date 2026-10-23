#pragma once
#include "process.h"
#include "ui.h"
#include <QLabel>
#include <QMainWindow>
#include <QPointer>
#include <QSettings>
#include <QSystemTrayIcon>
#include <QTemporaryDir>
#include <memory>

class Window : public QMainWindow {
  Q_OBJECT
  Q_CLASSINFO("D-Bus Interface", "org.yubiquity.Desktop")
public:
  Window(QString backend, QString vault, QString socket, QString helper);
  ~Window() override;
public slots:
  Q_SCRIPTABLE void Show();
  void screenLocked(bool locked);
  void sleepChanged(bool sleeping);

protected:
  void closeEvent(QCloseEvent *event) override;
  void changeEvent(QEvent *event) override;

private:
  QString backend, vault, socket, externalSocket, helper;
  QSettings settings;
  QProcess service, watch;
  QByteArray watchBuffer, serviceError, heldSecret;
  QTimer startup, heartbeat;
  int startupAttempts = 0;
  bool stopping = false, busy = false, sessionLocked = false,
       unlockOnConnect = false, hideWhenReady = false;
  SnapshotModel model;
  QString dismissedToken, displayedState;
  std::unique_ptr<QTemporaryDir> runtime;
  QPointer<ApprovalDialog> approval;
  QPointer<Command> command;
  QPointer<Pinentry> pinentry;
  QLabel *status, *detail, *vaultLabel, *sessionNote;
  QPushButton *unlock, *lock, *choose, *create, *hideToTray;
  QSystemTrayIcon *tray;
  void startService(bool askUnlock = false);
  void startWatch();
  void stopService();
  void failure(const QString &message);
  void readSnapshots();
  void applySnapshot();
  void dismissApproval();
  void hideInTray();
  void setBusy(bool value);
  void updateButtons();
  void selectVault(bool newVault);
  void promptSecret(bool newVault = false);
  void unlockWith(QByteArray secret);
  void runCommand(const QStringList &arguments, QByteArray secret,
                  bool secretInput,
                  std::function<void(bool, QByteArray, QString)> done);
  void lockVault();
  void monitorSession();
};
