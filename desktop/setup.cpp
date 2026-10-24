#include "setup.h"
#include "ui.h"
#include <QDesktopServices>
#include <QFile>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QScrollArea>
#include <QUrl>
#include <QVBoxLayout>
#include <sys/stat.h>

namespace {
QString diagnosticText(const QString &text) {
  QStringList lines;
  for (const auto &line : text.split('\n'))
    lines << displayText(QString(line).replace('\t', ' '));
  return lines.join("\n");
}
bool installedHelper() {
  // Never elevate a helper from a checkout, PATH, or a user-writable location.
  for (const char *path :
       {"/", "/usr", "/usr/sbin", "/usr/sbin/yubiquity-setup"}) {
    struct stat meta {};
    if (stat(path, &meta) || meta.st_uid != 0 || (meta.st_mode & 0022))
      return false;
  }
  struct stat meta {};
  const bool executable = !lstat("/usr/sbin/yubiquity-setup", &meta) &&
                          S_ISREG(meta.st_mode) && (meta.st_mode & 0111);
  // Older packages either lack desktop verbs or still require a group refresh.
  // Do not promise immediate access when a source GUI finds such a helper.
  QFile helperFile("/usr/sbin/yubiquity-setup");
  return executable &&
         helperFile.open(QIODevice::ReadOnly) &&
         helperFile.read(512).contains("# YubiQuity device access: user-acl-v1\n") &&
         !lstat("/usr/share/polkit-1/actions/org.yubiquity.setup.policy",
                &meta) &&
         S_ISREG(meta.st_mode) && meta.st_uid == 0 && !(meta.st_mode & 0022);
}
QLabel *label(const QString &text, QVBoxLayout *layout) {
  auto *item = new QLabel(text);
  item->setTextFormat(Qt::PlainText);
  item->setWordWrap(true);
  item->setTextInteractionFlags(Qt::TextSelectableByMouse);
  layout->addWidget(item);
  return item;
}
} // namespace

SetupPage::SetupPage(QString executable, QString nodeHelper, QWidget *parent)
    : QWidget(parent), backend(std::move(executable)),
      helper(std::move(nodeHelper)) {
  auto *layout = new QVBoxLayout(this);
  auto *scroll = new QScrollArea;
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto *content = new QWidget;
  auto *steps = new QVBoxLayout(content);
  steps->setSpacing(16);
  auto *heading = label(tr("Set up your security key"), steps);
  auto headingFont = heading->font();
  headingFont.setPointSize(headingFont.pointSize() + 5);
  headingFont.setBold(true);
  heading->setFont(headingFont);
  label(tr("Enable access, open a vault, then try a passkey in your browser."),
        steps);
  auto section = [steps](const QString &title) {
    auto *group = new QGroupBox(title);
    auto *items = new QVBoxLayout(group);
    items->setSpacing(10);
    steps->addWidget(group);
    return items;
  };
  auto *device = section(tr("1. Enable access on this computer"));
  checks = label(tr("Checking whether your account can use the security key…"),
                 device);
  checks->setObjectName("setupChecks");
  auto *actions = new QHBoxLayout;
  refresh = new QPushButton(tr("Check again"));
  refresh->setObjectName("setupCheck");
  deviceRepair = new QPushButton(tr("Enable access…"));
  deviceRepair->setObjectName("setupDevice");
  firefoxRepair = new QPushButton(tr("Allow Firefox Snap…"));
  firefoxRepair->setObjectName("setupFirefox");
  for (auto *button : {deviceRepair, firefoxRepair, refresh})
    actions->addWidget(button);
  actions->addStretch();
  device->addLayout(actions);
  result = label({}, device);
  result->setObjectName("setupResult");
  result->hide();
  auto *vault = section(tr("2. Open your vault"));
  vaultState = label({}, vault);
  auto *vaultActions = new QHBoxLayout;
  create = new QPushButton(tr("Create vault…"));
  create->setObjectName("setupCreate");
  open = new QPushButton(tr("Open vault…"));
  open->setObjectName("setupOpen");
  unlock = new QPushButton(tr("Unlock"));
  pin = new QPushButton(tr("Set security-key PIN…"));
  pin->setObjectName("setupPin");
  for (auto *button : {create, open, unlock})
    vaultActions->addWidget(button);
  vaultActions->addStretch();
  vault->addLayout(vaultActions);
  vault->addWidget(pin, 0, Qt::AlignLeft);
  label(tr("The vault passphrase encrypts your saved passkeys. The "
           "security-key PIN is what your browser asks for. Both allow "
           "unlimited attempts. A copied vault keeps its existing PIN."),
        vault);
  auto *browser = section(tr("3. Try your browser"));
  label(tr("On webauthn.io, enter a disposable username and register using "
           "“Security key”. Enter your PIN if asked, then click Approve in "
           "YubiQuity. Try signing in with the same username. This creates a "
           "test registration on the public site."),
        browser);
  auto *test = new QPushButton(tr("Open test site"));
  test->setObjectName("setupBrowserTest");
  browser->addWidget(test, 0, Qt::AlignLeft);
  label(tr("Test each browser you use. A successful device check alone does "
           "not verify the browser connection."),
        browser);
  auto *details = new QPushButton(tr("Show details"));
  details->setObjectName("setupShowDetails");
  details->setCheckable(true);
  steps->addWidget(details, 0, Qt::AlignLeft);
  diagnostics = label({}, steps);
  diagnostics->setObjectName("setupDetails");
  diagnostics->hide();
  connect(details, &QPushButton::toggled, this, [this, details](bool visible) {
    diagnostics->setVisible(visible);
    details->setText(visible ? tr("Hide details") : tr("Show details"));
  });
  steps->addStretch();
  scroll->setWidget(content);
  layout->addWidget(scroll);
  auto *done = new QPushButton(tr("Done"));
  done->setObjectName("setupDone");
  layout->addWidget(done);
  connect(refresh, &QPushButton::clicked, this, &SetupPage::check);
  connect(deviceRepair, &QPushButton::clicked, this,
          [this] { repair("device"); });
  connect(firefoxRepair, &QPushButton::clicked, this,
          [this] { repair("firefox"); });
  connect(create, &QPushButton::clicked, this, &SetupPage::createVault);
  connect(open, &QPushButton::clicked, this, &SetupPage::openVault);
  connect(unlock, &QPushButton::clicked, this, &SetupPage::unlockVault);
  connect(pin, &QPushButton::clicked, this, &SetupPage::configurePin);
  connect(done, &QPushButton::clicked, this, &SetupPage::finished);
  connect(test, &QPushButton::clicked, this, [this] {
    if (!QDesktopServices::openUrl(QUrl("https://webauthn.io")))
      message(tr("Could not open your default browser. Open "
                 "https://webauthn.io in the browser you want to test."));
  });
  setVaultState(false, false, false, false, false);
  updateRepairs();
}

void SetupPage::setVaultState(bool selected, bool ready, bool pinKnown,
                              bool configured, bool busy, bool manageVault) {
  create->setEnabled(manageVault && !busy && !ready);
  open->setEnabled(manageVault && !busy && !ready);
  unlock->setEnabled(selected && !busy && !ready);
  pin->setEnabled(ready && pinKnown && !busy);
  pin->setText(configured ? tr("Change security-key PIN…")
                          : tr("Set security-key PIN…"));
  vaultState->setText(
      ready ? (pinKnown
                   ? (configured ? tr("Vault unlocked. Its security-key PIN is "
                                      "configured; you can test your browser.")
                                 : tr("Vault unlocked. Set a security-key PIN "
                                      "before testing PIN-required passkeys."))
                   : tr("Vault unlocked. Waiting for PIN status; if it does "
                        "not appear, update both application components."))
            : (selected ? tr("Unlock your selected vault to check or set its "
                             "security-key PIN.")
                        : tr("Create a new vault or open a vault copied from "
                             "another computer.")));
}
void SetupPage::message(const QString &text) {
  result->setText(diagnosticText(text));
  result->setVisible(!text.isEmpty());
}
void SetupPage::updateRepairs() {
  refresh->setEnabled(!job);
  deviceRepair->setVisible(repairDevice);
  firefoxRepair->setVisible(repairFirefox);
  deviceRepair->setEnabled(!job && installedHelper());
  firefoxRepair->setEnabled(!job && installedHelper());
}
void SetupPage::showReport(const QJsonObject &report) {
  if (report.value("version").toInt() != 1 ||
      !report.value("checks").isArray()) {
    message(
        tr("Incompatible setup report. Update the GUI and backend together."));
    return;
  }
  QStringList lines;
  bool deviceReady = false, hidrawReady = false, needsAttention = false;
  for (const auto &value : report.value("checks").toArray()) {
    const auto check = value.toObject();
    const auto state = check.value("status").toString();
    const auto prefix = state == "ok"          ? tr("OK")
                        : state == "attention" ? tr("Action needed")
                        : state == "unknown"   ? tr("Unknown")
                        : state == "unchecked" ? tr("Not checked")
                                               : tr("Info");
    lines << tr("%1 — %2\n%3")
                 .arg(prefix, displayText(check.value("title").toString()),
                      diagnosticText(check.value("detail").toString()));
    const auto id = check.value("id").toString();
    if (id == "uhid")
      deviceReady = state == "ok";
    if (id == "hidraw")
      hidrawReady = state == "ok";
    needsAttention |= state == "attention" || state == "unknown";
  }
  diagnostics->setText(lines.join("\n\n"));
  repairDevice = report.value("repair_device").toBool();
  repairFirefox = report.value("repair_firefox").toBool();
  if (repairDevice)
    checks->setText(tr("Your account needs permission to create a software "
                       "security key. Enable access asks for administrator "
                       "authentication and takes effect immediately. No logout "
                       "or reboot is needed. Grant this only to trusted users."));
  else if (repairFirefox)
    checks->setText(tr("Firefox Snap needs permission to use this key. Choose "
                       "Allow Firefox Snap, then fully quit and reopen Firefox. "
                       "If your vault is unlocked, lock and unlock it again."));
  else if (needsAttention)
    checks->setText(tr("Some checks need attention. Open Show details below "
                       "for the cause and next steps, then Check again."));
  else if (deviceReady && hidrawReady)
    checks->setText(tr("Access is ready. Continue with your vault below."));
  else
    checks->setText(tr("Device access has not been confirmed. Choose Check "
                       "again to try a temporary key."));
  if ((repairDevice || repairFirefox) && !installedHelper())
    message(tr("Automatic repair requires the installed YubiQuity package. "
               "This build will not run a helper from the source checkout as "
               "administrator. Install the package, or follow "
               "docs/host-testing.md for source installation."));
  updateRepairs();
}
void SetupPage::check() {
  if (job)
    return;
  checks->setText(tr("Checking access with a temporary key… This check does "
                     "not load any credentials."));
  auto *command = new Command(this);
  job = command;
  updateRepairs();
  connect(command, &Command::finished, this,
          [this, command](bool ok, QByteArray output, const QString &error) {
            job = nullptr;
            command->deleteLater();
            if (ok)
              showReport(QJsonDocument::fromJson(output).object());
            else
              message(tr("Checks did not finish. No settings were changed.\n%1")
                          .arg(error));
            updateRepairs();
          });
  QStringList args{"doctor", "--json", "--probe"};
  if (!helper.isEmpty())
    args << "--node-helper" << helper;
  command->start(backend, args, {}, false, 60000);
}
void SetupPage::repair(const QString &action) {
  if (job || !installedHelper())
    return;
  auto *command = new Command(this);
  job = command;
  updateRepairs();
  message(tr("Waiting for the desktop administrator prompt. Cancelling it "
             "leaves setup available to retry."));
  connect(
      command, &Command::finished, this,
      [this, command](bool ok, QByteArray output, const QString &error) {
        job = nullptr;
        command->deleteLater();
        message(
            ok ? QString::fromUtf8(output).trimmed()
               : tr("Setup was cancelled or could not finish. Completed steps "
                    "may already have taken effect.\n%1\nIf no password window "
                    "appeared, check that your desktop has a polkit "
                    "authentication agent. You can also ask an administrator "
                    "to run sudo yubiquity-setup YOUR_USERNAME.")
                     .arg(error));
        check();
      });
  command->start("/usr/bin/pkexec",
                 {"--disable-internal-agent", "/usr/sbin/yubiquity-setup",
                  "--desktop-" + action},
                 {}, false, 120000);
}
