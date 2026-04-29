# Local Admin Scanner

Security auditing tool for discovering and analyzing members of local privileged groups on Active Directory endpoints.

---

## 🇬🇧 English

### What it does

**Local Admin Scanner** helps security and IT teams answer one key question:
> Who has local administrative access on domain computers right now?

The scanner:

- discovers computers from AD via LDAP (workstations and servers OUs),
- checks connectivity (WinRM/SMB/RDP probes),
- collects local group memberships (Administrators and optional groups),
- optionally expands domain groups via LDAP/GC,
- calculates per-host risk score/severity,
- saves scan artifacts (JSON/CSV/Summary),
- provides a web UI + API + analytics summary.

### Main capabilities

- **Adaptive remote collection**
  - WinRM first (when available),
  - RPC fallback (SMB) with adaptive behavior,
  - optional WMI fallback.
- **Performance controls**
  - thread limits,
  - network and RPC concurrency limits,
  - probe timeouts and host hard timeout,
  - LDAP/GC group expansion caps and workers.
- **Targeting controls**
  - include/exclude host patterns (`*`, `?`),
  - OS substring filter,
  - separate workstation/server OU targeting.
- **Operator UX**
  - presets (Stable Fast / Reliable Fast),
  - OU DN builder helper,
  - bilingual interface (EN/RU),
  - summary page with filtering, comparison, CSV export.

### Quick start

#### Requirements

- Python 3.10+
- Network reachability to AD/targets
- Service account with required read/remote permissions

#### Install

```bash
pip install fastapi uvicorn ldap3 pywinrm wmi jinja2
```

#### Run

```bash
python app.py
```

Open:

- `http://127.0.0.1:8000` — main scanner page
- `http://127.0.0.1:8000/summary` — analytics summary

### Output files

Each scan creates files in `results/` (or custom `save_path`):

```text
scan_YYYYMMDD_HHMMSS.json
scan_YYYYMMDD_HHMMSS.csv
summary_YYYYMMDD_HHMMSS.json
```

### API (selected)

- `POST /scan/start` — start scan
- `POST /scan/stop` — stop scan
- `GET /scan/status` — progress
- `GET /scan/results` — stream batch results
- `GET /api/summary` — latest summary
- `GET /api/scans` — list scan files
- `GET /api/diff` — compare two summaries
- `GET /download/{file}` — download artifact

### Security recommendations

- Use a dedicated least-privilege service account.
- Limit management protocol exposure (WinRM/WMI/RPC) by policy.
- Protect generated reports (they may contain sensitive account mapping).

---

## 🇷🇺 Русская версия

### Назначение

**Local Admin Scanner** помогает быстро понять:
> кто имеет локальные привилегии на компьютерах домена в текущий момент.

Сканер:

- получает список хостов из AD через LDAP (OU рабочих станций и серверов),
- проверяет доступность протоколов (WinRM/SMB/RDP),
- собирает участников локальных групп,
- при необходимости разворачивает доменные группы через LDAP/GC,
- рассчитывает риск и критичность по каждому хосту,
- сохраняет результаты в JSON/CSV/Summary,
- предоставляет Web UI, API и страницу сводной аналитики.

### Ключевые возможности

- **Адаптивный сбор**
  - приоритет WinRM,
  - RPC fallback (SMB),
  - опциональный WMI fallback.
- **Контроль производительности**
  - лимиты потоков,
  - ограничения сетевой и RPC-параллельности,
  - таймауты проб и жёсткий таймаут хоста,
  - лимиты/воркеры для разворота групп LDAP/GC.
- **Гибкий выбор объектов**
  - include/exclude маски (`*`, `?`),
  - фильтр по строке ОС,
  - отдельный выбор OU для рабочих станций и серверов.
- **Удобство оператора**
  - пресеты режимов (Stable Fast / Reliable Fast),
  - помощник сборки OU DN,
  - интерфейс EN/RU,
  - расширенная сводка с фильтрацией, сравнением и CSV-экспортом.

### Быстрый старт

#### Требования

- Python 3.10+
- сетевой доступ к AD и целевым хостам
- сервисная учётная запись с нужными правами

#### Установка

```bash
pip install fastapi uvicorn ldap3 pywinrm wmi jinja2
```

#### Запуск

```bash
python app.py
```

Открыть:

- `http://127.0.0.1:8000` — главная страница сканера
- `http://127.0.0.1:8000/summary` — сводка и аналитика

### Выходные файлы

По каждому запуску формируются файлы в `results/` (или в `save_path`):

```text
scan_YYYYMMDD_HHMMSS.json
scan_YYYYMMDD_HHMMSS.csv
summary_YYYYMMDD_HHMMSS.json
```

### Основные API-методы

- `POST /scan/start` — запуск сканирования
- `POST /scan/stop` — остановка
- `GET /scan/status` — статус/прогресс
- `GET /scan/results` — поток результатов
- `GET /api/summary` — последняя сводка
- `GET /api/scans` — список файлов сканов
- `GET /api/diff` — сравнение двух сводок
- `GET /download/{file}` — скачивание результата

### Рекомендации по безопасности

- Используйте отдельную сервисную учётную запись с минимально необходимыми правами.
- Ограничивайте доступ к WinRM/WMI/RPC на уровне политик и ACL.
- Храните отчёты в защищённом месте (они содержат чувствительные данные по доступам).

