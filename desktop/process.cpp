#include "process.h"
#include <QStandardPaths>
#include <csignal>
#include <sys/prctl.h>
#include <unistd.h>

void protectChild(QProcess &process, bool secretInput) {
  const auto parent = getpid();
  process.setChildProcessModifier([parent, secretInput] {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
      _exit(126);
    // Keep clear of Qt's low-numbered startup/error descriptors.
    if (secretInput && dup2(STDIN_FILENO, 198) < 0)
      _exit(126);
  });
}

void erase(QByteArray &bytes) {
  // Best effort only: Qt/process I/O may have made other copies. No promise of
  // locked-memory storage or protection from software running as this user.
  volatile char *p = bytes.data();
  for (qsizetype i = 0; i < bytes.size(); ++i)
    p[i] = 0;
  bytes.clear();
}

QByteArray assuanEscape(QByteArray text) {
  return text.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D");
}

bool assuanDecode(const QByteArray &text, QByteArray &result) {
  auto hex = [](char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  for (qsizetype i = 0; i < text.size(); ++i) {
    if (text[i] != '%')
      result.append(text[i]);
    else {
      if (i + 2 >= text.size())
        return false;
      const int hi = hex(text[i + 1]), lo = hex(text[i + 2]);
      if (hi < 0 || lo < 0)
        return false;
      result.append(char(hi * 16 + lo));
      i += 2;
    }
    if (result.size() > 1024)
      return false;
  }
  return true;
}

Command::Command(QObject *parent) : QObject(parent) {
  timeout.setSingleShot(true);
  connect(&timeout, &QTimer::timeout, this, [this] {
    complete(false, tr("The operation timed out. Lock and try again."));
  });
  connect(&process, &QProcess::errorOccurred, this,
          [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart)
              complete(false, process.errorString());
          });
  auto collect = [this] {
    output += process.readAllStandardOutput();
    errors += process.readAllStandardError();
    if (output.size() + errors.size() > 65536)
      complete(false, tr("Unexpectedly large service response."));
  };
  connect(&process, &QProcess::readyReadStandardOutput, this, collect);
  connect(&process, &QProcess::readyReadStandardError, this, collect);
  connect(&process, &QProcess::finished, this,
          [this, collect](int code, QProcess::ExitStatus status) {
            collect();
            complete(code == 0 && status == QProcess::NormalExit);
          });
}

void Command::start(const QString &binary, const QStringList &arguments,
                    QByteArray secret, bool secretInput) {
  protectChild(process, secretInput);
  process.start(binary, arguments);
  if (secretInput)
    process.write(secret);
  process.closeWriteChannel();
  erase(secret);
  timeout.start(30000);
}

void Command::complete(bool ok, const QString &error) {
  if (done)
    return;
  done = true;
  timeout.stop();
  if (process.state() != QProcess::NotRunning)
    process.kill();
  emit finished(ok, output,
                error.isEmpty() ? QString::fromUtf8(errors).trimmed() : error);
}

void Command::cancel() { complete(false, tr("Operation cancelled.")); }

Command::~Command() {
  if (process.state() != QProcess::NotRunning) {
    process.kill();
    process.waitForFinished(500);
  }
}

Pinentry::Pinentry(QObject *parent) : QObject(parent) {
  timeout.setSingleShot(true);
  connect(&timeout, &QTimer::timeout, this,
          [this] { fail(tr("Passphrase entry timed out.")); });
  connect(&process, &QProcess::readyReadStandardOutput, this, &Pinentry::read);
  // Do not log secret-prompt diagnostics or forward arbitrary Assuan errors.
  connect(&process, &QProcess::readyReadStandardError, this, [this] {
    auto data = process.readAllStandardError();
    erase(data);
  });
  connect(&process, &QProcess::errorOccurred, this,
          [this](QProcess::ProcessError) {
            fail(tr("Could not run pinentry-qt. Install it and launch "
                    "YubiQuity in your desktop session."));
          });
  connect(&process, &QProcess::finished, this, [this] {
    if (!done)
      fail(tr("Passphrase entry was cancelled."));
  });
}

void Pinentry::start(bool create) {
  auto binary = QStandardPaths::findExecutable("pinentry-qt");
  if (binary.isEmpty() || (qEnvironmentVariableIsEmpty("DISPLAY") &&
                           qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY"))) {
    fail(tr("A graphical desktop and pinentry-qt are required."));
    return;
  }
  commands = {
      "SETTITLE YubiQuity",
      "SETDESC " +
          assuanEscape(
              create ? QByteArray(
                           "Choose a vault passphrase (at least 12 "
                           "bytes).\nThis encrypts your saved passkeys. It is "
                           "separate from the browser's security-key PIN.")
                     : QByteArray(
                           "Unlock your YubiQuity vault.\nThis is the vault "
                           "passphrase, not the browser's security-key PIN.")),
      "SETPROMPT Vault passphrase:",
      "SETOK " + QByteArray(create ? "Create vault" : "Unlock"),
      "SETCANCEL Cancel",
      "SETTIMEOUT 120"};
  if (create)
    commands.append("SETREPEAT Confirm passphrase:");
  commands.append("GETPIN");
  protectChild(process);
  process.start(binary, {});
  timeout.start(125000);
}

void Pinentry::read() {
  buffer += process.readAllStandardOutput();
  if (buffer.size() > 8192) {
    fail(tr("Invalid passphrase-prompt response."));
    return;
  }
  while (buffer.contains('\n') && !done) {
    auto end = buffer.indexOf('\n');
    auto line = buffer.left(end);
    buffer.remove(0, end + 1);
    if (line.endsWith('\r'))
      line.chop(1);
    if (line.startsWith("D ") && readingSecret) {
      if (!assuanDecode(line.mid(2), secret)) {
        erase(line);
        fail(tr("Invalid or oversized passphrase."));
        return;
      }
    } else if (line == "OK" || line.startsWith("OK ")) {
      if (commands.isEmpty()) {
        done = true;
        timeout.stop();
        process.write("BYE\n");
        process.closeWriteChannel();
        emit secretReady(secret);
        erase(secret);
      } else {
        const auto command = commands.takeFirst();
        readingSecret = command == "GETPIN";
        process.write(command + '\n');
      }
    } else if (!line.startsWith("#") && !line.startsWith("S ")) {
      erase(line);
      fail(tr("Passphrase entry was cancelled or rejected."));
      return;
    }
    erase(line);
  }
}

void Pinentry::fail(const QString &message) {
  if (done)
    return;
  done = true;
  timeout.stop();
  process.kill();
  erase(secret);
  erase(buffer);
  emit failed(message);
}

void Pinentry::cancel() { fail(tr("Passphrase entry cancelled.")); }

Pinentry::~Pinentry() {
  done = true;
  if (process.state() != QProcess::NotRunning) {
    process.kill();
    process.waitForFinished(500);
  }
  erase(buffer);
  erase(secret);
}
