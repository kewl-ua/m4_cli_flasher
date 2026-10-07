[← README](../README.md)

# Linux

На Linux `dji-duml` работает через обычную libusb-1.0 из дистрибутива: ни
DJI Assistant, ни его драйвер не нужны. Проверено 2026-10-05 на Gentoo
(OpenRC, Python 3.14, libusb-1.0) с M4T на 16.01.0006: `scan`, `version`,
`manifest` и `params` дали те же ответы, что на Windows (манифест байт в
байт, таблица параметров с той же контрольной суммой), все тесты проходят.
**Прошивка (`flash`) на Linux ещё не запускалась.**

**1. Пакеты.** libusb-1.0, pyusb и git. На Gentoo:

```bash
sudo emerge --ask dev-libs/libusb dev-python/pyusb dev-vcs/git
```

В других дистрибутивах — их пакеты libusb и pyusb, либо виртуальное
окружение: `python -m venv ~/.venvs/dji`, затем `~/.venvs/dji/bin/pip install
pyusb` и запуск через `~/.venvs/dji/bin/python`. Системный `pip` в
системный Python ставить не даёт (PEP 668), и pyusb должен стоять для той
версии Python, которой запускается `python`.

**2. Доступ к дрону без root.** Правило udev для VID `2ca3` / PID `0020`
(папку `rules.d` может понадобиться создать):

```bash
sudo mkdir -p /etc/udev/rules.d
```

```bash
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="2ca3", ATTR{idProduct}=="0020", MODE="0660", GROUP="plugdev"' | sudo tee /etc/udev/rules.d/51-dji.rules
```

```bash
sudo groupadd -f plugdev
```

```bash
sudo gpasswd -a $USER plugdev
```

```bash
sudo udevadm control --reload-rules
```

```bash
sudo udevadm trigger
```

Затем перелогиниться и проверить, что `id` показывает `plugdev`.

**3. Проверка** (из папки проекта, всё только читает):

```bash
lsusb | grep -i 2ca3
```

```bash
python -m dji_duml scan
```

```bash
python -m dji_duml version
```

`scan` должен показать узел `libusb1` с `duml-interface=yes`. Если нужный
интерфейс занят драйвером ядра, `dji-duml` сам его отцепит; остальные
интерфейсы дрона (сеть RNDIS, накопитель) он не трогает.

Что стоит знать:

- **Не запускайте через `sudo`**: с правилом udev он не нужен. Под root
  хранилище прошивок по умолчанию может оказаться другим (у root своя
  домашняя папка), а в вашем могут появиться файлы root'а — смотря как
  `sudo` обходится с `HOME`. Файл блокировки `/tmp/dji-duml-m4t.lock`,
  созданный другим пользователем, `dji-duml` открывает только на чтение,
  так что смешанный запуск не ломает прошивку, но смешивать незачем.
- `lsusb` показывает в имени устройства серийный номер дрона: вырезайте его,
  прежде чем кому-то отправлять вывод.
- DJI Assistant под Linux нет, поэтому `fw harvest` по умолчанию не знает,
  где кэш: скопируйте `firm_cache` с Windows и укажите папку, или перенесите
  целиком хранилище прошивок — объекты в нём названы по SHA-256 и от ОС не
  зависят.
- USB-захват на Linux — через модуль ядра `usbmon` (`modprobe usbmon`) и
  `dumpcap`/`tshark`; `decode` и `extract` такие захваты читают.
- Предупреждения `DeprecationWarning` про `_pack_` из `usb/backend/libusb0.py`
  при запуске тестов на Python 3.14 идут из самого pyusb и на работу не влияют.
