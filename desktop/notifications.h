#pragma once
#include <QDBusConnection>
#include <QDBusMessage>
#include <QObject>

// One optional desktop notification for the current approval. Request tokens
// stay local: the desktop receives only generic text and a fixed action name.
class ApprovalNotification : public QObject {
  Q_OBJECT
public:
  explicit ApprovalNotification(QObject *parent = nullptr);
  ~ApprovalNotification() override;
  void show(const QString &request, bool unlock = false);
  void clear();
signals:
  // The controller must still check that this exact request is live.
  void activated(QString request);

private slots:
  void actionInvoked(uint id, const QString &action,
                     const QDBusMessage &message);
  void notificationClosed(uint id, uint reason, const QDBusMessage &message);

private:
  QDBusConnection bus;
  QString request, owner;
  uint notificationId = 0;
  quint64 generation = 0;
  bool unlocking = false;
  void close(const QString &serviceOwner, uint id);
  void send(const QString &serviceOwner, quint64 sequence);
};
