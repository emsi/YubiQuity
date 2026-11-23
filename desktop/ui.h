#pragma once
#include <QDialog>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QPushButton>
#include <QTimer>

QString displayText(const QString &value);

struct Pending {
  QString token, operation, rp, account;
  bool hasAccount = false;
  qint64 remaining = 0;
};

// Versioned snapshots are deliberately a tiny view model, not CTAP logic.
class SnapshotModel {
public:
  bool update(const QJsonObject &event, QString &error);
  QString state;
  QString credentialsRevision;
  bool pinKnown = false, pinConfigured = false;
  bool wakeSupported = false, wakeAvailable = false;
  Pending pending, unlockRequest;

private:
  qint64 sequence = 0;
};

class ApprovalDialog : public QDialog {
  Q_OBJECT
public:
  explicit ApprovalDialog(const Pending &request);
  void shortenLifetime(qint64 remaining);
  QString token() const { return request.token; }
  bool isLive() const { return !decided && elapsed.elapsed() < deadline; }
  void setWorking(bool working) { approve->setEnabled(!working && isLive()); }
  void showError(const QString &text);
signals:
  void decision(QString token, bool approve);
  void expired();

protected:
  void reject() override;

private:
  Pending request;
  QPushButton *approve;
  QElapsedTimer elapsed;
  QTimer timeout;
  qint64 deadline;
  bool decided = false;
  class QLabel *errorLabel;
  void choose(bool yes);
};
