# LAS — Local Admin Scanner

> Инструмент для аудита локальных привилегий на компьютерах Windows в доменной инфраструктуре Active Directory.

LAS (Local Admin Scanner) помогает инфраструктурным, системным и ИБ-командам отвечать на вопрос: **кто имеет локальные административные права на каких компьютерах прямо сейчас?**

Система получает компьютеры из Active Directory, проверяет доступность, собирает состав локальных групп, при необходимости раскрывает доменные группы, рассчитывает риск и предоставляет Web UI, API, экспорт и контролируемый remediation.

## Содержание
- Возможности
- Как работает LAS
- Архитектура
- Требования
- Установка
- Запуск
- Настройка сканирования
- Методы сбора
- Web UI и Summary
- Сравнение сканов
- Remediation
- Экспорт
- HTTP API
- Логирование
- Производительность
- Безопасность
- Troubleshooting
- Структура проекта
- Рекомендуемый процесс эксплуатации
- Ограничения
- Документация

## Возможности

### Аудит локальных привилегий
LAS собирает членов локальных групп Windows, включая:
- Administrators
- Remote Desktop Users
- Distributed COM Users
- Remote Management Users
- дополнительные группы, выбранные оператором.

Для найденного доступа сохраняются учётная запись, тип объекта, компьютер, локальная группа, прямой или групповой путь доступа и признаки риска.

### Active Directory
- получение компьютеров через LDAP;
- отдельная работа с OU рабочих станций и серверов;
- include/exclude маски;
- фильтр по ОС;
- LDAP/Global Catalog для расширения групп;
- ограничение глубины и объёма group expansion.

### Адаптивный сбор
Основные методы:
1. WinRM / PowerShell;
2. RPC / SMB fallback;
3. WMI, если компонент доступен.

Отсутствие WinRM не должно автоматически означать отсутствие данных: при подходящих сетевых разрешениях LAS может использовать альтернативный способ.

### Производительность
Поддерживаются ограничения количества потоков, сетевой и RPC-конкурентности, probe timeout, host hard timeout, LDAP/GC workers и group-expansion limits.

### Аналитика
Summary предоставляет общие показатели, рискованные машины, наиболее распространённые учётные записи, распределение доступа, детализацию машин, поиск, фильтрацию, heatmap, сравнение сканов и экспорт.

### Remediation
Можно удалять выбранную учётную запись из локальной группы непосредственно из UI либо с помощью сгенерированного PowerShell-скрипта.

Экспортируемый remediation использует WinRM первым методом, а при его ошибке — удалённый ADSI/RPC fallback. После операции выполняется проверка фактического отсутствия участника.

## Как работает LAS

```text
Active Directory
 |
 v
LDAP / Global Catalog
 |
 v
Список компьютеров
 |
 +---- include/exclude/OS filters
 |
 v
Connectivity probes
 |
 +---- WinRM
 +---- SMB/RPC
 +---- RDP
 |
 v
Remote collection
 |
 +---- PowerShell / WinRM
 +---- RPC / SMB
 +---- WMI (optional)
 |
 v
Local group memberships
 |
 v
LDAP/GC group expansion
 |
 v
Risk calculation
 |
 +---- JSON
 +---- CSV
 +---- summary JSON
 |
 v
Web UI / API / Diff / Remediation
```

## Архитектура
Проект является лёгким Python Web-приложением.

- FastAPI — backend и HTTP API;
- Jinja2 — HTML templates;
- ldap3 — LDAP/Active Directory;
- pywinrm — WinRM;
- WMI — дополнительный Windows management path;
- pywin32 — Windows RPC/NetAPI при наличии;
- JavaScript/CSS — интерактивный UI, фильтры, аналитика и remediation queue.

Основные результаты сохраняются в файлах и не требуют отдельной БД.

## Требования

### Сервер LAS
- Python 3.10+;
- DNS-разрешение доменных имён;
- сетевой доступ к Domain Controllers;
- сетевой доступ к целевым Windows-хостам;
- права сервисной учётной записи, достаточные для выбранных способов сбора.

Сервер приложения может работать на Windows. Linux также возможен, если необходимые Python-пакеты установлены и из него доступны используемые протоколы.

### Active Directory
Нужен LDAP-доступ к DC. Global Catalog требуется для сценариев, использующих GC group expansion.

### Windows targets
В зависимости от режима могут требоваться:
- WinRM TCP 5985/5986;
- SMB/RPC TCP 445 и необходимые RPC-порты;
- WMI/DCOM;
- RDP только для соответствующей connectivity probe.

## Установка

```bash
git clone https://github.com/aabandre/LAS.git
cd LAS
python -m venv .venv
```

Windows:
```powershell
.\.venv\Scripts\Activate.ps1
```

Linux:
```bash
source .venv/bin/activate
```

Базовые зависимости:
```bash
pip install fastapi uvicorn ldap3 pywinrm jinja2
```

Для WMI/Win32-сценариев:
```bash
pip install WMI pywin32
```

Если в конкретном deployment используется корпоративный файл зависимостей, следует устанавливать зависимости из него.

## Запуск

```bash
python app.py
```

По умолчанию:
- http://127.0.0.1:8000 — Web UI;
- http://127.0.0.1:8000/summary — Summary.

Для сетевого запуска:
```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

Для production рекомендуется HTTPS, reverse proxy, IP/ACL restrictions, отдельная сервисная учётная запись и защищённое хранение результатов.

## Настройка сканирования

### Targeting
Можно выбрать OU рабочих станций и серверов, include/exclude patterns и фильтр по ОС.

Примеры масок:
```text
BA-JES-*
SRV-*
*-RDP-*
```

### Производительность
Основные параметры: количество потоков, network concurrency, RPC concurrency, probe timeout, host hard timeout, LDAP/GC workers и group expansion limits.

Для большой инфраструктуры сначала рекомендуется тестовый запуск на небольшой OU, затем постепенное увеличение concurrency с контролем ошибок и нагрузки на DC.

В UI доступны пресеты Stable Fast и Reliable Fast.

## Методы сбора

### WinRM
Основной способ удалённого выполнения PowerShell. Даёт хороший контроль и структурированный вывод.

Типовые ошибки: WinRM cannot complete the operation, destination cannot be reached, WinRM is not set up to receive requests, Kerberos authentication failed, Access is denied.

### RPC / SMB
Fallback для получения информации о локальных группах. Позволяет работать с частью хостов, где WinRM недоступен.

### WMI
Дополнительный способ сбора, если установлен соответствующий Python-модуль и доступен DCOM/WMI.

## Web UI и Summary

Главная страница предназначена для настройки и запуска сканирования. Оператор выбирает AD-параметры, OU, группы, фильтры и производительность.

Summary доступна по /summary и показывает:
- общее число компьютеров;
- успешные и неуспешные проверки;
- рискованные хосты;
- локальных администраторов;
- распределение учётных записей;
- детализацию конкретного компьютера;
- heatmap Account ↔ Computer.

### Фильтрация и пагинация
Пагинация меняет только отображение текущей страницы. Экспорт использует весь логически отфильтрованный набор, поэтому при результате, например, 37 объектов и размере страницы 25 выгружаются все 37.

### Machine details
Для компьютера отображаются ОС, способ сбора, время, локальные группы, участники, вложенные группы и ошибки.

## Сравнение сканов
LAS позволяет сравнить два сохранённых скана и увидеть новые и исчезнувшие доступы, а также изменение количества рискованных машин.

Типовой цикл:
```text
Scan #1 -> Remediation -> Scan #2 -> Diff
```

## Remediation

### Web UI
Оператор выбирает аккаунт, компьютеры и локальную группу, добавляет их в remediation queue, проверяет список и подтверждает операцию.

Backend endpoint:
```text
POST /api/remediate/remove-local-admin
```

### PowerShell export
Сгенерированный скрипт:
1. пытается удалить участника через WinRM;
2. при ошибке WinRM использует удалённый ADSI/RPC;
3. перечисляет фактических членов локальной группы;
4. удаляет конкретный объект;
5. проверяет результат;
6. сохраняет метод и статус;
7. создаёт las-remediation-results.csv.

Статусы:
```text
Removed
AlreadyAbsent
RemovedUnverified
StillPresent
Failed
```

Методы:
```text
WinRM
ADSI-RPC
FAILED
```

Remediation является потенциально деструктивной операцией. Перед массовым запуском следует протестировать несколько машин, проверить необходимость удаления и сохранить исходный scan.

## Экспорт
Типичные файлы:
```text
results/
├── scan_YYYYMMDD_HHMMSS.json
├── scan_YYYYMMDD_HHMMSS.csv
└── summary_YYYYMMDD_HHMMSS.json
```

JSON предназначен для машинной обработки и хранения структуры результата. CSV удобен для Excel, Power BI, Python и аудита.

Экспорт администраторов из Summary содержит:
```text
account,type,count,via_group,machines
```

В machines перечисляются все компьютеры выбранного отфильтрованного набора. UTF-8 BOM добавляется для корректного открытия кириллицы в Excel.

## HTTP API

| Method | Endpoint | Назначение |
|---|---|---|
| POST | /scan/start | Запуск сканирования |
| POST | /scan/stop | Остановка |
| GET | /scan/status | Статус и прогресс |
| GET | /scan/results | Получение результатов |
| GET | /api/summary | Последняя сводка |
| GET | /api/scans | Список сканов |
| GET | /api/diff | Сравнение сканов |
| POST | /api/remediate/remove-local-admin | Удаление локального администратора |
| GET | /download/{file} | Скачивание артефакта |

API может использоваться внутренними системами автоматизации и отчётности.

## Логирование
Основной лог: scan.log.

Лог содержит события запуска/завершения, LDAP/WinRM/RPC/WMI ошибки, время обработки и диагностические сообщения. Используется rotating file handler.

Для диагностики временно включайте debug logging и после расследования возвращайте обычный уровень.

## Производительность
Основные ограничения обычно задаются сетью, WinRM, SMB/RPC, DC, DNS и LDAP, а не CPU Python-процесса.

Рекомендуемый подход:
1. тест 10–50 машин;
2. анализ scan.log и Summary;
3. постепенное увеличение concurrency;
4. контроль нагрузки Domain Controllers.

Не следует устанавливать максимальную параллельность только ради минимального времени полного скана.

## Безопасность

Используйте отдельную сервисную учётную запись с минимально необходимыми правами.

Не рекомендуется использовать Domain Admin без необходимости, хранить пароль в исходном коде или передавать его через небезопасные каналы.

Ограничивайте сетевую связность LAS с DC, GC, WinRM, SMB/RPC и WMI.

Результаты могут содержать имена машин, учётные записи, членство групп и сведения о привилегиях. Каталог результатов должен быть защищён.

Доступ к remediation endpoint должен быть разрешён только доверенным операторам.

## Troubleshooting

### WinRM
```powershell
Test-WSMan COMPUTERNAME
winrm quickconfig
```
Проверить DNS, TCP 5985/5986, Kerberos, SPN, firewall, WinRM policy и права.

### RPC / SMB
```powershell
Test-NetConnection COMPUTERNAME -Port 445
```
Проверить SMB, RPC Endpoint Mapper, firewall, необходимые службы и права.

### LDAP
Проверить DNS DC, TCP 389/636, TCP 3268/3269 для GC, bind credentials, LDAP filters и доступность DC.

### Некорректная кириллица
LAS содержит обработку типичных проблем кодировок Windows/PowerShell и передаёт структурированный вывод в UTF-8 payload. При проблемах проверить code page, locale и PowerShell output encoding.

### Недоступный компьютер
Недоступный компьютер нельзя автоматически считать чистым. Проверить DNS, маршрутизацию, SMB, WinRM, RPC, credentials, firewall и scan.log.

## Структура проекта

```text
LAS/
├── app.py
├── templates/
│ ├── index.html
│ └── summary.html
├── docs/
│ ├── UI_OPERATOR_GUIDE_RU.md
│ └── CONFLUENCE_UI_GUIDE_RU.md
├── results/
├── scan.log
├── README.md
└── README_EN.md
```

app.py содержит backend, scan engine, LDAP, WinRM, RPC/WMI, API, сохранение результатов и remediation.

templates содержит Web UI, Summary, фильтры, экспорт, diff и remediation queue.

docs содержит операторскую документацию.

## Рекомендуемый процесс эксплуатации

```text
1. Scan
 ↓
2. Summary
 ↓
3. Risk analysis
 ↓
4. Identify unwanted access
 ↓
5. Remediation
 ↓
6. New scan
 ↓
7. Diff
 ↓
8. Report
```

Такой цикл позволяет получить доказуемый результат до и после remediation.

## Ограничения
LAS не заменяет PAM, SIEM, EDR, Microsoft Defender for Identity, Group Policy или CMDB.

Назначение LAS — инвентаризация, анализ, сравнение и контролируемое remediation локальных привилегий Windows.

## Документация
- docs/UI_OPERATOR_GUIDE_RU.md — инструкция оператора;
- docs/CONFLUENCE_UI_GUIDE_RU.md — версия для Confluence;
- README_EN.md — английская документация.

## Репозиторий
https://github.com/aabandre/LAS

## Лицензия
Если отдельный файл лицензии отсутствует, условия использования определяются владельцем проекта.