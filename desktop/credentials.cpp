#include "credentials.h"
#include "ui.h"
#include <QHeaderView>
#include <QHideEvent>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QShowEvent>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

CredentialsPage::CredentialsPage(QString executable, QWidget *parent)
    : QWidget(parent), backend(std::move(executable)) {
  setObjectName("passkeysPage");
  auto *layout = new QVBoxLayout(this);
  message = new QLabel;
  message->setObjectName("passkeysStatus");
  message->setTextFormat(Qt::PlainText);
  message->setWordWrap(true);
  layout->addWidget(message);
  auto *actions = new QHBoxLayout;
  search = new QLineEdit;
  search->setObjectName("passkeysSearch");
  search->setPlaceholderText(tr("Search sites, names or passkey IDs"));
  search->setClearButtonEnabled(true);
  search->setAccessibleName(tr("Search passkeys"));
  actions->addWidget(search);
  refresh = new QPushButton(tr("Refresh"));
  refresh->setObjectName("passkeysRefresh");
  actions->addWidget(refresh);
  unlock = new QPushButton(tr("Unlock vault"));
  unlock->setObjectName("passkeysUnlock");
  actions->addWidget(unlock);
  layout->addLayout(actions);
  model = new QStandardItemModel(0, 5, this);
  model->setHorizontalHeaderLabels({tr("Site"), tr("Username"),
                                    tr("Display name"), tr("Discoverable"),
                                    tr("Passkey ID")});
  filter = new QSortFilterProxyModel(this);
  filter->setSourceModel(model);
  filter->setFilterCaseSensitivity(Qt::CaseInsensitive);
  filter->setSortCaseSensitivity(Qt::CaseInsensitive);
  filter->setFilterKeyColumn(-1);
  table = new QTableView;
  table->setObjectName("passkeysTable");
  table->setModel(filter);
  table->setColumnHidden(4, true); // Full identifiers remain searchable.
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setSortingEnabled(true);
  table->sortByColumn(0, Qt::AscendingOrder);
  table->verticalHeader()->hide();
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  layout->addWidget(table, 1);
  details = new QLabel;
  details->setObjectName("passkeyDetails");
  details->setTextFormat(Qt::PlainText);
  details->setWordWrap(true);
  details->setTextInteractionFlags(Qt::TextSelectableByMouse |
                                   Qt::TextSelectableByKeyboard);
  layout->addWidget(details);
  connect(search, &QLineEdit::textChanged, this, [this](const QString &text) {
    filter->setFilterFixedString(text);
    updateCount();
    updateDetails();
  });
  connect(table->selectionModel(), &QItemSelectionModel::selectionChanged, this,
          &CredentialsPage::updateDetails);
  connect(refresh, &QPushButton::clicked, this, &CredentialsPage::reload);
  connect(unlock, &QPushButton::clicked, this,
          &CredentialsPage::unlockRequested);
  updateAvailability();
}

void CredentialsPage::clear() {
  ++generation;
  if (command) {
    command->disconnect(this);
    command->cancel();
    command->deleteLater();
    command = nullptr;
  }
  staged = {};
  ids.clear();
  total = -1;
  model->removeRows(0, model->rowCount());
  details->clear();
}

void CredentialsPage::setContext(const QString &endpoint, bool ready,
                                 const QString &nextRevision) {
  if (socket == endpoint && unlocked == ready && revision == nextRevision)
    return;
  clear();
  socket = endpoint;
  unlocked = ready;
  revision = nextRevision;
  if (!unlocked)
    search->clear();
  updateAvailability();
  if (isVisible() && unlocked && !revision.isEmpty())
    reload();
}

void CredentialsPage::updateAvailability() {
  const bool available = unlocked && !revision.isEmpty() && !socket.isEmpty();
  refresh->setEnabled(available && !command);
  search->setEnabled(available);
  unlock->setVisible(!unlocked);
  message->setText(
      !unlocked    ? tr("Unlock your vault to view stored passkeys.")
      : !available ? tr("This service does not support listing passkeys. "
                        "Update the backend and desktop app together.")
                   : tr("Open this tab or refresh to view stored passkeys."));
}

void CredentialsPage::showEvent(QShowEvent *event) {
  QWidget::showEvent(event);
  reload();
}

void CredentialsPage::hideEvent(QHideEvent *event) {
  clear();
  search->clear();
  updateAvailability();
  QWidget::hideEvent(event);
}

void CredentialsPage::reload() {
  clear();
  updateAvailability();
  if (!isVisible() || !unlocked || revision.isEmpty() || socket.isEmpty())
    return;
  message->setText(tr("Loading passkeys…"));
  readPage(0);
}

void CredentialsPage::failed(const QString &text) {
  clear();
  updateAvailability();
  message->setText(text);
}

void CredentialsPage::readPage(int offset) {
  auto *job = new Command(this);
  command = job;
  refresh->setEnabled(false);
  const auto epoch = generation;
  connect(
      job, &Command::finished, this,
      [this, job, epoch, offset](bool ok, const QByteArray &output,
                                 const QString &) {
        job->deleteLater();
        if (epoch != generation || command != job || !unlocked || !isVisible())
          return;
        command = nullptr;
        const auto response = QJsonDocument::fromJson(output).object();
        if (!ok || !response.value("ok").toBool()) {
          failed(response.value("error").toString(
              tr("Could not load passkeys. Refresh to try again.")));
          return;
        }
        const auto page = response.value("credentials").toObject();
        const auto items = page.value("items").toArray();
        const auto count = page.value("total").toInteger(-1);
        const auto nextValue = page.value("next_offset");
        const auto next = nextValue.toInteger(-1);
        const auto end = offset + items.size();
        auto invalid = [this] {
          failed(tr("Invalid or changed passkey list. Refresh to try again."));
        };
        // Bound UI memory even for a faulty peer. This exceeds the number of
        // credentials that the current 1 MiB encrypted vault can hold.
        if (response.value("state") != "ready" ||
            response.value("credentials_revision") != revision ||
            !page.value("items").isArray() || !page.contains("next_offset") ||
            count < 0 || count > 10000 || (total >= 0 && total != count) ||
            end > count ||
            (nextValue.isNull()
                 ? end != count
                 : (next != end || next <= offset || next >= count))) {
          invalid();
          return;
        }
        total = int(count);
        static const QRegularExpression identifier("^[0-9a-f]{64}$");
        static const QRegularExpression handle("^(?:[0-9a-f]{2}){1,64}$");
        for (const auto &value : items) {
          const auto item = value.toObject();
          const auto id = item.value("credential_id").toString();
          const auto rp = item.value("rp_id").toString();
          auto nameValid = [&item](const char *field) {
            auto name = item.value(field);
            return name.isNull() ||
                   (name.isString() && name.toString().toUtf8().size() <= 64);
          };
          if (!identifier.match(id).hasMatch() || ids.contains(id) ||
              rp.isEmpty() || rp.toUtf8().size() > 253 || !nameValid("name") ||
              !nameValid("display_name") ||
              !item.value("discoverable").isBool() ||
              !handle.match(item.value("user_handle").toString()).hasMatch()) {
            invalid();
            return;
          }
          ids.insert(id);
          staged.append(item);
        }
        if (!nextValue.isNull()) {
          readPage(int(next));
          return;
        }
        populate();
      });
  job->start(backend,
             {"control", "--socket", socket, "credentials", "--offset",
              QString::number(offset), "--revision", revision},
             {}, false, 5000);
}

void CredentialsPage::populate() {
  for (const auto &value : staged) {
    const auto item = value.toObject();
    auto name = [&item, this](const char *field) {
      const auto text = item.value(field).toString();
      return text.isEmpty() ? tr("Not provided") : displayText(text);
    };
    QList<QStandardItem *> row;
    for (const auto &text :
         {displayText(item.value("rp_id").toString()), name("name"),
          name("display_name"),
          item.value("discoverable").toBool() ? tr("Yes") : tr("No"),
          item.value("credential_id").toString()})
      row << new QStandardItem(text);
    row[0]->setData(item, Qt::UserRole);
    model->appendRow(row);
  }
  staged = {};
  ids.clear();
  refresh->setEnabled(true);
  updateCount();
  if (filter->rowCount())
    table->selectRow(0);
}

void CredentialsPage::updateCount() {
  if (!unlocked || command || total < 0)
    return;
  message->setText(
      total == 0 ? tr("No passkeys are stored in this vault yet.")
                 : tr("%1 of %2 passkeys. Names are supplied by the site.")
                       .arg(filter->rowCount())
                       .arg(total));
}

void CredentialsPage::updateDetails() {
  const auto selected = table->selectionModel()->selectedRows();
  if (selected.isEmpty()) {
    details->clear();
    return;
  }
  const auto item = filter->data(selected.first(), Qt::UserRole).toJsonObject();
  auto name = [&item, this](const char *field) {
    const auto text = item.value(field).toString();
    return text.isEmpty() ? tr("Not provided") : displayText(text);
  };
  details->setText(tr("Site: %1\nUsername: %2\nDisplay name: %3\nPasskey ID: "
                      "%4\nAccount identifier: %5")
                       .arg(displayText(item.value("rp_id").toString()),
                            name("name"), name("display_name"),
                            item.value("credential_id").toString(),
                            item.value("user_handle").toString()));
}
