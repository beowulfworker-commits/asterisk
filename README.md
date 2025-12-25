# Asterisk (PJSIP) Debian 12 — install.sh

Минимальный воспроизводимый установщик: Asterisk (PJSIP) + 12 SIP пользователей + nftables + fail2ban.

## Запуск
1) Скопируйте репозиторий на чистую VPS с Debian 12.
2) Запустите:
   sudo ./install.sh

## Конфигурация через /etc/voip-install.env
Файл опционален. Если он есть — значения берутся из него. Пример:

SIP_USERS_BASE=1001
SIP_USERS_COUNT=12
SIP_PASSWORD_MODE=random
SIP_PASSWORD_PRESET=MyStrongPass-{ext}
SIP_PORT=5060
RTP_PORT_START=10000
RTP_PORT_END=20000
LOCAL_NET=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
TIMEZONE=Europe/Warsaw
ALLOW_SSH_FROM=

## Режимы
- sudo ./install.sh
- sudo ./install.sh --dry-run
- sudo ./install.sh --reconfigure
- sudo ./install.sh --reset-users
- sudo ./install.sh --set SIP_PORT=5062

## Где учётки
/root/voip_credentials.txt  (права 600)

## Порты
- SSH: 22/tcp (опционально ограничивается ALLOW_SSH_FROM)
- SIP: 5060/udp (или SIP_PORT)
- RTP: 10000-20000/udp (или RTP_PORT_START..RTP_PORT_END)

## Подключение софтфона (Zoiper / Linphone)
- Host/Domain: публичный IP сервера
- Port: 5060
- Transport: UDP
- Username: 1001..1012
- Password: см. /root/voip_credentials.txt
- Codecs: PCMU/PCMA (ulaw/alaw)
