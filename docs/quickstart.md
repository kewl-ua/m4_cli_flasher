[← README](../README.md)

# Быстрый старт

Проверить связь (только чтение):

```powershell
dji-duml scan       # ровно у одного узла должно быть duml-interface=yes
dji-duml version    # hardware WA345T AC Ver.A, firmware 17.02.0501
dji-duml manifest   # что ровно стоит: версия и все модули с MD5
```

Посмотреть пакет и управляющие кадры будущей прошивки (USB не нужен):

```powershell
dji-duml inspect M4T_UAV_17.02.05.01_pro.zip
dji-duml plan M4T_UAV_17.02.05.01_pro.zip
```

Прошить:

```powershell
dji-duml --journal dji-duml-journal/flash.jsonl flash M4T_UAV_17.02.05.01_pro.zip `
    --target 17.02.0501 --expected-current 17.01.0516 --yes
```

- `--target` — версия пакета (сверяется с манифестом внутри пакета),
  `--expected-current` — версия на дроне сейчас (сверяется с дроном).
- Для той же версии добавить `--refresh`.
- Принимаются и офлайн-ZIP, и `dji_system.bin`.
- Ничего не трогать до `Installed …` или ошибки: передача ~1 мин, установка
  с одной-двумя перезагрузками дрона — ещё 2–7 мин (весь прогон — от 3,5 до
  7,5 мин). Ctrl+C дрон не останавливает.
- Ход прошивки — по строке на этап. На терминале передача и каждый отрезок
  установки между перезагрузками перерисовываются полосой в одной строке:
  у передачи — со скоростью и оставшимся временем, у установки — со
  временем её начала. В файл или конвейер полоса пишется отдельными
  строками не чаще чем через 10 %. `-v` печатает каждый отчёт о ходе
  отдельной строкой, как раньше:

```text
[10:51:07] preflight
[10:51:07] enter
[10:51:08] transfer  [##############################] 100%  11.6 MB/s  in 0:57
[10:52:06] start  requesting the install
[10:52:06] verify
[10:52:07] upgrading [############------------------]  41%  install since 10:52:06
[10:54:15] reboot  the device restarts; reconnecting
[10:54:59] upgrading [##########################----]  87%  install since 10:52:06
[10:58:11] reboot  the device restarts; reconnecting
[10:58:28] upgrading [##############################] 100%  install since 10:52:06
[10:58:31] confirm  the device reports success; reading the installed version
[10:58:35] done  17.02.0501
Installed 17.02.0501 (was 14.01.0012) in 449 s.
```

Это прогон 14.01.0012 → 17.02.0501 на третьем дроне. Строку `confirm`
печатает текущая версия; в том прогоне на её месте была третья `reboot`.

Прогон на эмуляторе без дрона: `dji-duml --simulate 17.01.0516 flash ...`.

Достать из USB-захвата файлы, которые Assistant или dji-duml передали
дрону (USB не нужен):

```powershell
dji-duml extract capture.pcap -o extracted
```

Каждый файл сверяется с размером и MD5 из кадров передачи и с подписанным
манифестом `.cfg.sig` из того же захвата; не прошедший проверку сохраняется
как `<имя>.incomplete`, причины — на экране и в `extracted\report.json`.
Код выхода: 0 — всё сошлось, 2 — нет, 1 — захват не прочитан. Подробно — в
[docs/duml.md](duml.md#файлы-прошивки-из-захвата-extract).

Собрать из извлечённых файлов пакет для `flash` — так версию, которую
Assistant однажды скачал из сети и передал дрону под USB-захватом, можно
потом ставить без Assistant и интернета:

```powershell
dji-duml extract downgrade_14_usb.pcap -o 14.01.0012_extracted
dji-duml pack 14.01.0012_extracted -o 14.01.0012_dji_system.bin
dji-duml flash 14.01.0012_dji_system.bin --target 14.01.0012 --expected-current 17.01.0516 --yes
```

`pack` берёт `.cfg.sig` и все модули её подписанного манифеста, сверяет
каждый с размером и MD5 из манифеста, собирает несжатый tar, как
`dji_system.bin` (конфигурация, затем модули в порядке манифеста), и
перечитывает его так, как это сделает `flash`. Файлы `*.incomplete` не
берутся; если в папке есть `report.json` от `extract`, `.cfg.sig` должна
быть в нём целой. Так у третьего дрона прошёл откат на 14.01.0012.
