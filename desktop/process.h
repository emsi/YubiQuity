#pragma once
#include <QByteArray>
#include <QObject>
#include <QProcess>
#include <QTimer>
#include <functional>

// No shell, secret arguments/environment, or cross-user socket implementation.
// Each child dies when its GUI parent dies, including on SIGKILL.
void protectChild(QProcess &process, bool secretInput = false);
void erase(QByteArray &bytes);
QByteArray assuanEscape(QByteArray text);
bool assuanDecode(const QByteArray &text, QByteArray &result);

class Command : public QObject {
  Q_OBJECT
public:
  explicit Command(QObject *parent = nullptr);
  ~Command() override;
  void start(const QString &binary, const QStringList &arguments,
             QByteArray secret = {}, bool secretInput = false);
  void cancel();
signals:
  void finished(bool ok, QByteArray output, QString error);

private:
  QProcess process;
  QTimer timeout;
  QByteArray output, errors;
  bool done = false;
  void complete(bool ok, const QString &error = {});
};

// A small Assuan client to the established desktop secret prompt. No caching.
class Pinentry : public QObject {
  Q_OBJECT
public:
  explicit Pinentry(QObject *parent = nullptr);
  ~Pinentry() override;
  void start(bool create);
  void cancel();
signals:
  void secretReady(QByteArray secret);
  void failed(QString message);

private:
  QProcess process;
  QTimer timeout;
  QByteArray buffer, secret;
  QList<QByteArray> commands;
  bool done = false;
  bool readingSecret = false;
  void read();
  void fail(const QString &message);
};
