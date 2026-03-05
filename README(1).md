# Local Admin Scanner

Active Directory Local Administrators auditing tool.

------------------------------------------------------------------------

# 🇬🇧 English

## Overview

**Local Admin Scanner** is a security auditing tool designed to detect
and analyze members of the **local Administrators group** across
computers in an Active Directory environment.

The scanner automatically:

-   discovers computers via LDAP
-   connects remotely using WinRM or WMI
-   retrieves local administrators
-   expands domain groups via LDAP
-   calculates risk scores
-   generates analytics and reports

The system includes a **web interface**, **REST API**, and **analytics
dashboard**.

------------------------------------------------------------------------

## Key Features

### Infrastructure Discovery

-   LDAP discovery of computers from Active Directory
-   Separate OU scanning for:
    -   Workstations
    -   Servers
-   DNS caching
-   Parallel scanning

------------------------------------------------------------------------

### Administrator Detection

The scanner tries multiple methods automatically:

1.  WinRM + ADSI\
2.  WinRM + Get-LocalGroupMember\
3.  WinRM + net localgroup\
4.  WMI fallback

------------------------------------------------------------------------

### Domain Group Expansion

If a domain group is found inside local Administrators:

-   it is expanded via LDAP
-   nested groups are resolved recursively
-   users are mapped with **via_group**

Example:

    DOMAIN\Admins
       └── DOMAIN\User1
       └── DOMAIN\User2

------------------------------------------------------------------------

### Risk Scoring

Each machine receives a calculated risk score.

Example logic:

  Event                Score
  -------------------- -------
  Custom admin         +10
  Unauthorized admin   +20
  Builtin admin        0

Severity levels:

    clean
    low
    medium
    high
    critical

------------------------------------------------------------------------

### Analytics Dashboard

The dashboard provides:

-   top administrator accounts
-   domain group usage
-   risky machines
-   OS statistics
-   port statistics
-   admin heatmap
-   scan comparison (diff)

------------------------------------------------------------------------

### Reports

Each scan generates:

    results/
     ├── scan_YYYYMMDD_HHMMSS.json
     ├── scan_YYYYMMDD_HHMMSS.csv
     └── summary_YYYYMMDD_HHMMSS.json

------------------------------------------------------------------------

### API Endpoints

  Endpoint             Description
  -------------------- -------------------
  `/scan/start`        Start scan
  `/scan/stop`         Stop scan
  `/scan/status`       Scan progress
  `/scan/results`      Stream results
  `/api/summary`       Latest analytics
  `/api/scans`         List scan history
  `/api/diff`          Compare two scans
  `/download/{file}`   Download report

------------------------------------------------------------------------

## Architecture

                    +----------------------+
                    |      Web UI          |
                    |  HTML + JavaScript   |
                    +----------+-----------+
                               |
                         REST API (FastAPI)
                               |
                +--------------+--------------+
                |                             |
         LDAP Discovery                 Remote Execution
                |                             |
         Active Directory            WinRM / WMI scanning
                |
           Group Expansion
                |
           Risk Analysis
                |
            Report Engine
                |
          JSON / CSV / Summary

------------------------------------------------------------------------

## Installation

### Requirements

Python **3.10+**

------------------------------------------------------------------------

### Install dependencies

    pip install fastapi uvicorn ldap3 pywinrm wmi jinja2

------------------------------------------------------------------------

## Run

    python app.py

Server will start at:

    http://127.0.0.1:8000

------------------------------------------------------------------------

## Configuration

Inside the web UI specify:

  Parameter           Description
  ------------------- -------------------
  Domain Controller   AD LDAP server
  Domain              FQDN domain
  NetBIOS Domain      NetBIOS name
  Username            service account
  Password            credentials
  Workstations OU     OU for PCs
  Servers OU          OU for servers
  Max Threads         parallel scanning
  Allowed Admins      whitelist

------------------------------------------------------------------------

## Use Cases

Security teams can use the tool for:

-   auditing Domain Admin exposure
-   detecting shadow administrators
-   identifying misconfigured machines
-   compliance checks
-   incident response

------------------------------------------------------------------------

## Security Notes

Recommendations:

-   use a dedicated service account
-   restrict WinRM access
-   store reports securely

------------------------------------------------------------------------

# 🇷🇺 Русская версия

## Описание

**Local Admin Scanner** --- инструмент аудита локальной группы
**Администраторы** на компьютерах в Active Directory.

Сканер автоматически:

-   получает список компьютеров через LDAP
-   подключается к ним через WinRM или WMI
-   собирает участников локальной группы администраторов
-   разворачивает доменные группы через LDAP
-   рассчитывает уровень риска
-   формирует аналитические отчёты

------------------------------------------------------------------------

## Возможности

### Поиск компьютеров

-   получение компьютеров из Active Directory
-   сканирование OU рабочих станций
-   сканирование OU серверов
-   многопоточное выполнение

------------------------------------------------------------------------

### Получение администраторов

Используются несколько методов:

1.  WinRM + ADSI\
2.  WinRM + Get-LocalGroupMember\
3.  WinRM + net localgroup\
4.  WMI

------------------------------------------------------------------------

### Разворачивание доменных групп

Если в локальных администраторах присутствует доменная группа:

-   она раскрывается через LDAP
-   разворачиваются вложенные группы
-   показывается через какую группу получен доступ

------------------------------------------------------------------------

### Аналитика

В интерфейсе доступны:

-   топ администраторов
-   статистика по группам
-   risky machines
-   статистика ОС
-   статистика портов
-   heatmap администраторов
-   сравнение сканов

------------------------------------------------------------------------

### Отчёты

После сканирования создаются:

    results/
     ├── scan_TIMESTAMP.json
     ├── scan_TIMESTAMP.csv
     └── summary_TIMESTAMP.json

------------------------------------------------------------------------

## Использование

1.  Ввести параметры подключения к AD\
2.  Указать OU\
3.  Нажать **Start Scan**\
4.  Дождаться завершения\
5.  Скачать отчёты

------------------------------------------------------------------------

## License

MIT License
