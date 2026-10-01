# Kali WSL MCP

MCP для работы агентов с Kali Linux через WSL. Python 3.11+, MCP Python SDK v2.
Версия 0.2: **36 tools, 18 профилей**, stdio и локальный Streamable HTTP.

[![Checks](https://github.com/Kelll31/KaliWSL-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/Kelll31/KaliWSL-MCP/actions/workflows/ci.yml)

## Что умеет

- Очередь: 4 работающих процесса и до 64 ожидающих задач по умолчанию. Пакеты проверяются
  до запуска; таймаут начинается после выхода из очереди.
- Запуск утилит с literal argv, без shell. На Linux отмена посылает SIGTERM, затем
  SIGKILL всей группе процессов. Дочерние процессы завершаются и после выхода основного.
- Индекс SQLite WAL для метаданных, пагинация истории и кэш executable paths.
  Старые engagement автоматически импортируются; JSON sidecars и evidence сохраняются.
- Потоковый Nmap XML / JSONL, чтение JSONL по байтовому курсору, ffuf и WhatWeb JSON.
- Tail, поиск по логам, SHA-256, UTF-8 без потери символов на границе страниц, base64
  для бинарных артефактов, компактные сводки сервисов и severity.
- Отдельные лимиты stdout/stderr, файлов задания и размера ответа MCP.
- IP/CIDR/домены/wildcard scope с исключениями. Пересечение CIDR с исключением отклоняется.
- Находки с дедупликацией и статусами, импорт Nuclei, заметки для передачи работы агенту.
- Отчёты Markdown и JSON с evidence и историей выполнения.
- Общая очередь для нескольких HTTP-клиентов; отключение одного клиента не отменяет её.

## Установка в Windows + Kali WSL

Клонируйте репозиторий в PowerShell:

~~~powershell
git clone https://github.com/Kelll31/KaliWSL-MCP.git
Set-Location KaliWSL-MCP
$linuxRoot = (& wsl.exe -d kali-linux --exec wslpath -a (Get-Location).Path).Trim()
wsl.exe -d kali-linux --cd $linuxRoot --exec bash scripts/install-kali.sh
~~~

Из Kali Linux без WSL: `bash scripts/install-kali.sh`. Имя окружения `.venv-kali`
одинаково в обоих вариантах. Kali WSL должна быть установлена; имя дистрибутива можно
проверить через `wsl.exe --list --quiet`.

Скрипт использует существующий .venv-kali, устанавливает зависимости из requirements.lock
и обновляет editable package. config.local.json создаётся только при отсутствии.
Для установки инструментов разработки передайте --dev. При отсутствии ensurepip
установите в Kali sudo apt install python3-venv.

Утилиты Kali устанавливаются отдельно:

~~~bash
sudo apt update
sudo apt install nmap curl dnsutils whatweb ffuf sslscan
~~~

tools_inventory показывает установленные executables и доступные профили.
Nuclei требует заранее установленных templates. Сервер не устанавливает пакеты и не обновляет
templates при запуске заданий. Дополнительные профили используют Nikto, testssl.sh,
Subfinder и smbclient; для работы с ними установите соответствующие утилиты.

## Совместимость с kali-linux-large

MCP запускает CLI-утилиты внутри Kali и обнаруживает их через PATH. Метапакет
`kali-linux-large` не устанавливает каждый инструмент из каталога MCP.
После установки или обновления пакетов выполните в Kali:

~~~bash
.venv-kali/bin/python scripts/check-kali.py
~~~

Проверка читает статус метапакета, разрешает имена executable и сверяет флаги профилей
с локальной справкой. Она не запускает сканирование. `--strict` возвращает ошибку,
если отсутствует хотя бы один профиль; `--output /path/report.json` сохраняет отчёт.
Агенты получают актуальную доступность через `tools_inventory(refresh=True)`
и `environment_check`, включая Linux distribution и CAP_NET_RAW / CAP_NET_ADMIN.

Для команды `httpx` MCP предпочитает ProjectDiscovery `httpx-toolkit`. Python CLI
из `python3-httpx` с тем же именем не считается ProjectDiscovery.
`testssl.sh` также разрешается в `testssl`, `httpie` — в `http`,
`enum4linux-ng` — в `enum4linux-ng.py`; NetExec и netcat поддерживают парные имена.
Allowlist проверяет запрошенное логическое имя перед запуском alias.
`scan_plan` показывает фактический executable, который использует очередь.

В проверенной установке `kali-linux-large 2026.3.9` доступны 16 из 18 профилей:
`tls_audit` и `subdomains` требуют отдельно установленных `testssl.sh` и `subfinder`.
Флаги Nmap, curl, WhatWeb, ffuf, sslscan, Nuclei, Nikto, smbclient и httpx-toolkit
проверены на установленных версиях. Доступность бинарника не гарантирует нужные
privileges, templates, credentials или возможности WSL для конкретного задания.
UDP/raw sockets требуют соответствующих capabilities; Wi-Fi monitor mode и доступ
к USB-оборудованию зависят от устройств и настроек WSL. Для остальных CLI можно
дополнить `allowed_tools` и использовать `run_tool`.

## Подключение через stdio

Готовый файл: [examples/mcp-client.json](examples/mcp-client.json).

~~~json
{
  "mcpServers": {
    "kali": {
      "command": "wsl.exe",
      "args": [
        "-d", "kali-linux",
        "--cd", "/mnt/e/github/KaliWSL-MCP",
        "--exec", "/mnt/e/github/KaliWSL-MCP/.venv-kali/bin/python",
        "-m", "kali_mcp", "--config", "config.local.json"
      ]
    }
  }
}
~~~

Замените путь, если репозиторий расположен иначе. Ручной запуск:
powershell -NoProfile -File scripts/start-wsl.ps1.

Один stdio-процесс владеет одним workspace. Для отдельных клиентов передайте
--workspace /home/your-user/.local/share/kali-mcp/client-a или параметр -Workspace
PowerShell launcher. Блокировка предотвращает два одновременных запуска на одном workspace.

## Несколько агентов через HTTP

Внутри Kali задайте KALI_MCP_HTTP_TOKEN случайным токеном длиной минимум 32 символа
и запустите общий сервер:

~~~bash
.venv-kali/bin/python -m kali_mcp --config config.local.json \
  --transport streamable-http --host 127.0.0.1 --port 8765
~~~

Клиенты подключаются к http://127.0.0.1:8765/mcp с заголовком
Authorization: Bearer <token>. HTTP-клиент, поддерживающий custom headers:

~~~json
{
  "mcpServers": {
    "kali-shared": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
~~~

Токен берётся только из environment, параметр --token-env меняет имя переменной.
Обязательная Bearer-проверка и защита SDK от DNS rebinding действуют на MCP endpoint.
Сервер принимает только loopback bind. Доступ из Windows зависит от localhost forwarding
WSL. HTTP-клиенты с общим токеном разделяют доступ ко всему workspace. Это локальный
транспорт со статическим токеном, OAuth discovery / выдача токенов не реализованы.

## Конфигурация

~~~json
{
  "workspace": ".kali-mcp",
  "allowed_targets": ["127.0.0.0/8", "::1", "localhost"],
  "excluded_targets": [],
  "max_concurrent": 4,
  "max_queued": 64,
  "max_timeout": 3600,
  "max_output_bytes": 16777216,
  "max_artifact_bytes": 268435456,
  "max_response_bytes": 131072,
  "terminate_grace_seconds": 2.0,
  "profile_rate_limit": 50
}
~~~

Добавляйте рабочие цели в config.local.json. По умолчанию разрешён loopback.
allowed_tools заменяет стандартный список executables. max_queued: 0 выключает
ожидание и возвращает ошибку при занятом лимите.

*.example.com включает поддомены, но не сам example.com. В engagement можно включить
wildcard, если он помещается в scope оператора. Исключения оператора и engagement
проверяются вместе. Scope проверяет имена/адреса, без автоматического DNS pinning.

Относительный workspace разрешается относительно config-файла. Для скорости WSL
размещайте state на Linux filesystem, например /home/your-user/.local/share/kali-mcp.
Существующие результаты не перемещаются автоматически. KALI_MCP_CONFIG задаёт config path
через environment. --workspace переопределяет state path для конкретного процесса.

profile_rate_limit — верхняя граница rate одного задания в профилях Nmap, Nuclei, ffuf.
Она не ограничивает суммарный rate нескольких задач и raw run_tool.

## Профили

| Категория | Профили |
| --- | --- |
| Сеть | ports, ports_quick, ports_full, ports_udp, discovery, service_audit |
| HTTP / web | http_headers, http_probe, web_fingerprint, web_content, web_audit, nuclei |
| DNS / домены | dns, subdomains, whois |
| TLS | tls, tls_audit |
| SMB | smb_shares |

profile_list выдаёт описания, доступность и допустимые options.
ports использует TCP connect, -Pn, лёгкое определение версии; ports_quick — top 100
без version probing; ports_full — 1..65535. UDP требует raw socket privileges.
service_audit запускает banner, SSH host key, TLS certificate и HTTP NSE checks.
Опции rate, timing, threads и ports валидируются; shell flags через options не принимаются.
Рецепт recon_plan выбирает начальные проверки по типу цели и установленным утилитам.

## Tools

| Задача | Tools |
| --- | --- |
| Окружение | system_info, environment_check, tools_inventory, profile_list |
| Engagement | engagement_create, engagement_list, engagement_get, scope_check |
| Запуск | scan_plan, scan_start, scan_batch, recon_plan, recon_start, run_tool |
| Задания | job_status, job_list, job_output, jobs_wait, job_cancel, jobs_cancel |
| Артефакты | artifact_list, artifact_info, artifact_read, artifact_tail, artifact_search, artifact_parse, artifact_summary, input_write |
| Находки | finding_add, finding_list, finding_get, finding_update, finding_import |
| Заметки / отчёт | note_add, note_list, report_generate |

Resources: kali://profiles и kali://workflow. Prompt: pentest_workflow.

## Рабочий процесс

1. Проверьте environment_check и profile_list.
2. Создайте engagement с targets и optional excluded_targets.
3. Просмотрите recon_plan или scan_plan.
4. Используйте scan_start / recon_start либо scan_batch:

~~~json
{
  "engagement_id": "<id>",
  "scans": [
    {"profile": "ports_quick", "target": "127.0.0.1", "options": {"ports": "80,443"}},
    {"profile": "http_probe", "target": "http://127.0.0.1:8080", "timeout": 60}
  ]
}
~~~

5. Передайте возвращённые job IDs в jobs_wait. job_output возвращает статус и оба
   потока вместе; при продолжении передавайте stdout_offset / stderr_offset.
6. Читайте нужные строки через artifact_tail / artifact_search или получите artifact_summary.
   JSONL страницы продолжаются по next_cursor, XML и JSON arrays — по next_offset.
7. finding_import принимает Nuclei JSONL, отбрасывает out-of-scope results и создаёт
   unverified findings. Повторный импорт объединяет evidence, без дублей.
8. finding_update задаёт open / confirmed / false_positive / resolved.
   note_add сохраняет промежуточные выводы. report_generate создаёт report.md и report.json.

finding_list по умолчанию возвращает compact metadata. Полный текст читается через
finding_get или findings/<id>.json. Ответы ограничены max_response_bytes на payload
до сериализации SDK; служебная оболочка MCP и дублирование text/structured content
увеличивают фактический размер сообщения. При превышении уменьшайте limit.

input_write создаёт immutable UTF-8 файл до 64 KiB, возвращает absolute_path.
Передавайте его как wordlist профиля web_content либо аргумент утилиты.
artifact_read(encoding="base64") подходит для бинарных файлов. checksum=True в artifact_info
добавляет SHA-256 и stable flag: меняющийся файл нельзя считать окончательным evidence.

## Границы выполнения и хранения

run_tool передаёт literal argv, работает в каталоге задания, stdin закрыт.
Объявленный target проверяется, произвольные адреса и файлы внутри args не контролируются.
Утилиты имеют права пользователя Kali, могут читать host files, писать вне job directory
и запускать другие программы. Scope/allowlist не являются сетевым или файловым sandbox.

Лимит stdout+stderr общий для задания. Каталог задания измеряется примерно раз в секунду
и при завершении; quota может быть превышена между измерениями. Она не контролирует
записи вне каталога задания. Это не hard disk quota. Хранение engagement не ограничено
автоматической retention; завершённые результаты остаются на диске.

Состояния: queued, running, completed, failed, cancelled, timed_out, output_limit,
artifact_limit, interrupted. После аварийного завершения runtime незавершённые задания
помечаются interrupted; старые процессы не принимаются под управление автоматически.
Обычный stdio disconnect закрывает runtime и отменяет его задания.
В HTTP задания продолжаются до остановки общего сервера.

JSON sidecars сохраняются для переноса. SQLite является рабочим индексом; ручные правки
JSON во время работы не импортируются обратно. Для восстановления индекса после переноса
сохраняйте artifacts/sidecars и создавайте новый workspace без catalog.sqlite3.
Не изменяйте state files, пока сервер работает. Вывод утилит, notes и импортированные
findings — untrusted data. Подтверждение находки фиксирует оценку агента/оператора,
а не независимую проверку MCP.

## Проверки и разработка

~~~bash
uv sync --frozen --extra dev
uv run --frozen --extra dev ruff format --check .
uv run --frozen --extra dev ruff check .
uv run --frozen --extra dev python -m pytest -q
~~~

requirements.lock содержит версии и hashes runtime-зависимостей для pip.
CI использует uv.lock на Linux и Windows с Python 3.11 / 3.12 / 3.14.
Отдельный job собирает wheel / sdist, проверяет состав архивов и запуск установленного wheel.

Сборка для распространения:

~~~bash
uv build
python scripts/check-dist.py
~~~

Локальные настройки `config.local.json`, окружения `.venv*`, токены `.env*` и результаты
`.kali-mcp*` исключены из Git. Для запуска скопируйте `config.example.json` в
`config.local.json`; установщик делает это автоматически. В sdist входят только исходники,
тесты, примеры, скрипты, документация и файлы зависимостей. Проверка архива отклоняет
локальные настройки и evidence. При выборе собственного workspace храните его вне
репозитория либо добавьте его каталог в `.gitignore`.

Правила изменений: [CONTRIBUTING.md](CONTRIBUTING.md).
Описание версии: [CHANGELOG.md](CHANGELOG.md).

Реальная локальная проверка из PowerShell:

~~~powershell
.venv/Scripts/python.exe scripts/smoke.py --wsl
~~~

Она проверяет Windows → MCP → Kali → Nmap на 127.0.0.1:1, XML parsing и оба отчёта.
Из Kali: .venv-kali/bin/python scripts/smoke.py.
Проверки используют отдельный workspace .kali-mcp/smoke-nmap, поэтому совместимы
с уже запущенным основным сервером. Дополнительная проверка curl/WhatWeb/ffuf:
.venv-kali/bin/python scripts/web-smoke.py (временный loopback HTTP fixture,
workspace .kali-mcp/smoke-web).
Повторная проверка окружения `kali-linux-large`: `.venv-kali/bin/python scripts/check-kali.py`.

Benchmark без сетевых действий:

~~~bash
.venv-kali/bin/python scripts/benchmark.py --records 20000
~~~

На синтетических 20 000 записях в проверенном Kali WSL:
первая страница JSONL — 21,25 → 0,21 MiB peak, 0,0221 → 0,0020 s;
Nmap XML — 65,37 → 0,61 MiB peak, 0,6351 → 0,5331 s.
Измерения включают tracemalloc и зависят от окружения/входных данных.

Reference: [MCP SDK](https://py.sdk.modelcontextprotocol.io/v2/),
[Nmap](https://nmap.org/book/man-performance.html), [ffuf](https://github.com/ffuf/ffuf).
