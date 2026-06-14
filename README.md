# Проверка module_3

Скрипт запускается на HQ-CLI от `root`. Проверьте адреса, пароли и ожидаемые параметры в `.env`.

```bash
cd module_3_test
chmod +x 01-check-module-3.sh
./01-check-module-3.sh
```

Автоматически проверяются пункты `1-9`. Пункты `10-13`, включая Fail2ban
в пункте `11`, выводятся как `N/A`. Итог рассчитывается из 9 баллов.

Fail2ban проверяется вручную командой:

```bash
fail2ban-client status sshd
```

Проверить только формат таблицы:

```bash
./01-check-module-3.sh --self-test
```
