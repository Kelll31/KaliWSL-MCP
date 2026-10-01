# Разработка

Из корня репозитория с Python 3.11+ и uv:

~~~bash
uv sync --frozen --extra dev
uv run --frozen --extra dev ruff format --check .
uv run --frozen --extra dev ruff check .
uv run --frozen --extra dev python -m pytest -q
~~~

Тесты используют временные каталоги. Проверки Linux process groups пропускаются
на Windows. Для проверки поведения Kali установите dev-зависимости через
`bash scripts/install-kali.sh --dev` и выполните `.venv-kali/bin/python -m pytest -q`.
Реальные smoke-проверки и benchmark описаны в README; smoke использует только loopback.

Изменения поведения сопровождать тестом, который проверяет результат или воспроизводит
исправленную ошибку. При изменении MCP tools, профилей или конфигурации обновлять README
и публичные примеры. В PR указать проблему, новое поведение и выполненные проверки.

После изменения зависимостей обновить оба lock-файла:

~~~bash
uv lock
uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file requirements.lock
~~~

Для проверки упаковки выполнить `uv build` и `python scripts/check-dist.py`.
CI дополнительно устанавливает wheel в отдельное окружение и проверяет CLI.

Не добавлять в коммиты `config.local.json`, HTTP-токены, записи трафика и результаты
engagement. Для примеров использовать loopback или адреса документационных диапазонов.
В issue и PR прикладывать минимальное воспроизведение с удалёнными секретами и данными
заказчика. При обнаружении уязвимости сервера не публиковать активные credentials.
