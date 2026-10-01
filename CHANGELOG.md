# Changelog

## Unreleased

- Автоматические папки отчётов по цели и UTC; Windows report_root через wslpath.
- Журнал заданий с командой/argv, портом/сервисом, exit code, raw и причинами отказов.
- Полные redacted-копии stdout/stderr; оригиналы evidence сохраняются без изменений.
- report_status, report_step_add и report_summary_update; итоговые факты и гипотезы разделены.
- Восстановление snapshots/Summary, экспорт текстовых evidence и reporting smoke-сценарий.
- Nikto web_audit исключает DoS-категорию 6.

## 0.2.0

Первая версия для публикации.

- 36 MCP tools и 18 профилей для Kali Linux / Kali WSL.
- Stdio и общий локальный Streamable HTTP с Bearer authentication.
- Очередь заданий, пакетный запуск, отмена групп процессов и лимиты вывода.
- SQLite WAL, пагинация, потоковый разбор Nmap XML / JSONL и чтение артефактов.
- Scope с исключениями, находки с дедупликацией, заметки и отчёты Markdown / JSON.
- Установщик Kali, PowerShell launcher и примеры MCP-клиентов.
- Проверки Windows / Linux, локальные smoke-сценарии и benchmark парсеров.
- Lock-файлы зависимостей и проверка состава wheel / sdist.
- Проверка CLI-совместимости kali-linux-large; исправлены имена httpx-toolkit и testssl.
