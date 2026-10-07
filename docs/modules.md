[← README](../README.md)

# Устройство пакета

| Модуль | Что делает |
|---|---|
| `frame.py`, `crc.py`, `version.py` | кадр DUML v1, CRC8/CRC16, версии DJI |
| `transport.py`, `libusb_win32.py` | USB: выбор узла MI04, pyusb или DLL от DJI |
| `client.py` | запрос/ответ, очередь push-кадров, автоответы, keep-alive, журнал |
| `commands.py` | полезные нагрузки команд и разбор ответов |
| `package.py` | ZIP / `dji_system.bin`: манифест, версия, файлы, MD5 |
| `flasher.py` | автомат прошивки: `upgrade-center` (M4T) и `legacy-ftp` |
| `profiles.py` | константы модели (M4T) с источниками |
| `pcap.py` | разбор USBPcap / usbmon / pcapng |
| `extract.py` | файлы из передач `00/2A` в захвате, с проверкой по MD5 и манифесту |
| `pack.py` | пакет как `dji_system.bin` из извлечённых файлов, по манифесту |
| `store.py` | хранилище прошивок: объекты по SHA-256, индекс, версии из манифестов, экспорт, проверка |
| `ingest.py` | что и как кладётся в хранилище: пакеты, захваты, вывод `extract`, папки, кэш Assistant |
| `display.py` | вывод хода прошивки: строка на этап, полоса прогресса |
| `sim.py` | эмулятор дрона и центра обновления M4T для тестов и `--simulate` |
| `installed.py`, `params.py` | чтение манифеста установленной прошивки и параметров полётного контроллера |
| `battery.py` | чтение данных смарт-батареи (`0D/02`): напряжение, ток, ёмкость, температура, заряд |
| `writes.py` | запись одного параметра полётного контроллера (`03/E3`): валидация, обратная вычитка, обратимость |
| `roles.py` | роль модуля по имени файла (камера, gimbal, ESC, батарея, IMU…) для `manifest --roles` |
| `cli.py` | `scan`, `version`, `inspect`, `plan`, `decode`, `manifest`, `params`, `set-param`, `battery`, `probe`, `serial-scan`, `extract`, `pack`, `fw`, `flash` |
