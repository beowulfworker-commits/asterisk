# VoIP Cloud-init (Debian 12 + Asterisk PJSIP)

Этот комплект делает полностью готовый к использованию Asterisk (PJSIP) сервер при первом запуске VPS через cloud-init.

## Что получится
- Debian 12 + Asterisk (PJSIP)
- 12 SIP пользователей (по умолчанию 1001–1012)
- Внутренние звонки между ними
- nftables firewall (SSH + SIP + RTP)
- fail2ban (бан по попыткам подбора SIP)
- Файл с учетками: /root/voip_credentials.txt
- Лог установки: /var/log/voip-bootstrap.log

## Как использовать
1) Создайте VPS с образом **Debian 12**.
2) В панели VPS включите **cloud-init / user-data** и вставьте содержимое `cloud-init/user-data.yaml`.
3) В `user-data.yaml` обязательно замените SSH ключи в секции пользователя `voipadmin`.
4) Дождитесь первого запуска (обычно несколько минут), затем зайдите по SSH:
   - `ssh voipadmin@<SERVER_IP>`
5) Посмотрите результат:
   - `sudo cat /root/voip_credentials.txt`
   - `sudo tail -n 200 /var/log/voip-bootstrap.log`

## Подключение софтфона (Zoiper / Linphone)
Параметры:
- **Domain/Host**: публичный IP сервера
- **Port**: 5060
- **Transport**: UDP
- **Username**: 1001 (или другой)
- **Password**: из `/root/voip_credentials.txt`
- **Codecs**: PCMU/PCMA (ulaw/alaw)

## Звонки
Наберите номер другого пользователя (например 1002) — вызов пойдет через `Dial(PJSIP/1002)`.

## Важно
- Если вы задаёте `ALLOW_SSH_FROM`, укажите корректный ваш IP/CIDR, иначе можно закрыть SSH доступ.
- Скрипт идемпотентный: при повторном запуске не ломает систему и не меняет пароли, если файл пользователей уже создан.
