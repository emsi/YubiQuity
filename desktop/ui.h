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
  Pending pending;

private:
  qint64 sequence = 0;
};

class ApprovalDialog : public QDialog {
  Q_OBJECT
public:
  ApprovalDialog(const Pending &request, QWidget *parent = nullptr);
  void shortenLifetime(qint64 remaining);
  QString token() const { return request.token; }
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
  void choose(bool yes);
};
