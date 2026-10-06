# Калибровка виженов в DJI Assistant (RE) — и почему её нет у Matrice 4T

Реверс функции **vision calibration** из DJI Assistant 2 (Enterprise Series) и
ответ на вопрос, почему для Matrice 4T (`wa345t`) её нет. Источники: распакованный
Electron-бандл Assistant (`app.asar` → `/build/*.js`), дампы строк нативных бинарей
`DJIVisionCalibration{,2,3}.dll`, `DJI_guidance.dll`, `DJIService.exe`,
драйверные INF-файлы и прошивка M4T `17.02.05.01`. Всё — **статический анализ,
железо не трогали**. Серийники/координаты здесь не приводятся.

Выводы адверсариально перепроверены (каждый claim против самих артефактов).
Маркеры: `[C]` — подтверждено (строка/файл процитированы), `[c]` — кандидат/вывод,
`[i]` — обоснованный **вывод** (следует из фактов, но в самих артефактах прямо
не записан).

> **Брендинг.** UI — это «DJI Assistant 2 (Enterprise Series)» (webpack-бандл),
> но нативный бэкенд в `DJIEngine\` заклеймён «DJI Assistant 3 \ DJIEngine»
> (PDB `DJIService.pdb`, `DJIDevice.pdb`) `[C]`. То есть Assistant 2 Enterprise
> поставляется с общим бэкендом Assistant-3 — не путать с версией.

---

## Главный вывод (TL;DR)

1. Калибровка виженов — это **нативный image-pipeline**, а не DUML: UI по
   локальному WebSocket командует нативным движком, движок через **GuidanceSDK
   (libusb0)** напрямую говорит с SoC виженов. `[C]`
2. Функция гейтится **двумя независимыми фильтрами**: (а) клиентский per-codename
   allowlist, зашитый в сами `DJIVisionCalibration*.dll`; (б) серверный per-user
   whitelist из облака DJI (`IsUserInVisionWhiteList` → `/api/v2/assistant/flags`). `[C]`
3. **M4T (`wa345t`) отсутствует в allowlist всех трёх DLL** `[C]`, у него нет
   vision-USB-устройства, к которому мог бы прицепиться GuidanceSDK `[i]`, а обход
   препятствий у него **радарный (RD03 ×4) + fisheye**, а не стерео-камеры под
   оптическую калибровку `[C]`. Поэтому ручной калибровки виженов для M4T нет.
4. Снять **реальный** протокол калибровки можно на поддерживаемом борте — чисто
   на **Matrice 30 (`pm430`)**. M350 этим тулчейном не поддержан, M300 — под
   вопросом (см. §8). `[C]`

---

## 1. Архитектура (end-to-end)

```
 Assistant UI (webpack: aircraft.js + ws.js)
      │  ws://localhost  (Qt5WebSockets, AES на проводе)
      ▼
 DJIService.exe  (DJIWebSocketServer / DJIWebSocketHandler; общий бэкенд Assistant-3)
      │  загружает (механизм выбора не доказан строками — см. §11)
      ▼
 DJIVisionCalibration{,2,3}.dll  (OpenCV: детекция сетки кругов, расчёт искажений)
      │  GuidanceSDK API
      ▼
 DJI_guidance.dll  (GuidanceSDK)  ──libusb0 bulk/interrupt──►  SoC виженов борта
```

`[C]` цепочка подтверждена: `ws.js` строит URL `wsHost*/controller/vision_calibration/`;
`DJIService.exe` содержит `DJIWebSocketServer`/`DJIWebSocketHandler` (Qt5WebSockets);
`DJI_guidance.dll` резолвит `libusb0.dll` и экспортит vision-API; PDB
`dji-vision-calibrator-win\…\DJI_guidance.pdb` привязывает SDK к калибратору.

---

## 2. WebSocket-слой

Хост и порты (`ws.js`, модуль 1047) `[C]`: `host = localStorage['wsHost'] || 'localhost'`,
схема всегда `ws://`, порты фиксированы:

| Константа | URL | Назначение |
|---|---|---|
| `wsHost`  | `ws://localhost:19870` | сервис `calibration_assist` |
| `wsHost2` | `ws://localhost:19871` | сервис `calibration_common` |
| `wsHost3` | `ws://localhost:9999`  | прочее |
| `wsHost4` | `ws://localhost:19881` | прочее |

> Порты 19870/19871 — **клиентские** константы из `ws.js`; в бинарях сервера как
> литералы не найдены (`QWebSocketServer::listen` с рантайм-портом), так что
> bind-порт сервера — вывод из клиента `[i]`.

**Один путь, два сервиса.** И `calibration_common`, и `calibration_assist`
подключаются к одному пути `/controller/vision_calibration/<FILE>` (`FILE` = id
активного устройства), но на разные порты и с разными наборами команд. `[C]`

**Исходящие команды `calibration_common` (:19871)** — основной флоу: `[C]`

| Команда (WS verb) | Аргументы | Алиас |
|---|---|---|
| `vision_calibration_init` | DEVICE, WIDTH, HEIGHT, SCREEN_WIDTH, SCREEN_HEIGHT, VERSION, CALIBRATION_TYPE | initVisionCalibration |
| `vision_calibration_config_screen_size` | — | (self) |
| `vision_calibration_set_screen_size` | VALUE | (self) |
| `vision_calibration_set_cam_pair` | INDEX | setCamPair |
| `vision_calibration_enter_match_rect` | COUNT | enterMatchRect |
| `vision_calibration_enter_track` | COUNT | enterTrack |
| `vision_calibration_start_calculation` | — | startCalculation |
| `vision_calibration_stop` | — | stop |

**Исходящие команды `calibration_assist` (:19870)** — обслуживание/станционный тест: `[C]`
`upload_calibrate_info[INFO]`, `trigger_station_test[]`,
`transfer_calibrate_result_file[]`, `enter_low_power[]`, `exit_low_power[]`.

**Входящие события (сервер → UI)** — найдены в бандлах `aircraft.js/m210.js/m410.js/wm240.js`: `[C]`
- статус: `…_init_ok`, `…_init_cali_status`, `…_match_rect_ok`, `…_track_ok`,
  `…_track_x_ok`, `…_track_y_ok`, `…_calculation_ok`, `…_set_calculation_progress`,
  `…_set_record_information`, `…_plot_cmd`, `…_background_plot_cmd`;
- подсказки оператору: `…_warn_aim_to_screen`, `…_warn_no_pattern`,
  `…_warn_move_forward`, `…_warn_move_backward`, `…_warn_rotate_left`,
  `…_warn_rotate_right`, `…_warn_obstruction`, `…_warn_clear`;
- ошибки: `…_error_init_fail`, `…_error_calc_error`, `…_error_camera_disconnect`,
  `…_error_low_light`, `…_error_move_too_much`, `…_error_screen_too_small`,
  `…_error_invalid_screen`, `…_error_invalid_screen_size`;
- потоки картинок: `…_camera_images`, `…_pattern_image_foreground`,
  `…_pattern_image_background`, `…_miniguide_image`.

На проводе сообщения **AES-шифрованы** (`ws.js` держит `secret_key_enc/dec`,
`encrypt()/decrypt()` поверх `utils.aes_*`; флаг `develop` жёстко `false`), а
потоки картинок исключены из логов (`log_events_black_list`). `[C]`

---

## 3. Движки калибровки (vc1 / vc2 / vc3)

Три поколения DLL, все на **OpenCV 2.4.13.7** (встроенные build-пути
`…\opencv-2.4.13.7\modules\calib3d\src\calibration.cpp`). `[C]`

- **`DJIVisionCalibration.dll` (vc1)** — первое поколение, «BoardCalibration»/P4:
  OpenCV `SimpleBlobDetector`/`findCirclesGrid`, строки `BoardCalibration.cpp`,
  `detect pattern time(ms)`, `{"type":"circle"}`. **Нет** `OpenCVext`/`calialg`
  и пути `dji_perception`. `[C]`
- **`DJIVisionCalibration2.dll` / `3.dll` (vc2/vc3)** — движок «Guidance/EagleCamera»:
  `OpenCVext`, `calialg`/`calialg::PlaneSpec`, детекция сетки кругов
  (`too few circles`, `wrong align circles`, `too many/few rings`), пишет в
  `/factory_data/dji_perception`. vc3 — новейший (`dji-vision-calibration-3-win`). `[C]`

То есть калибратор — это компьютерное зрение на ПК: борт показывают камерой на
экран с паттерном (сетка кругов), оператора ведут подсказками поворота/сдвига,
финальный расчёт искажений идёт на ПК.

---

## 4. GuidanceSDK — транспорт (`DJI_guidance.dll`)

Это **отдельный USB-стек, не DUML**. `[C]` PDB `…\dji-vision-calibrator-win\…\DJI_guidance.pdb`,
Qt-слинкован (`Qt5Core`).

- **libusb0 напрямую** (не наш `libusb0_dji`): динамически резолвит `libusb0.dll`
  через `LoadLibraryA`/`GetProcAddress`; использует `usb_bulk_read/write`,
  `usb_interrupt_read/write`, `usb_claim_interface`, `usb_set_altinterface`,
  `usb_get_descriptor_by_endpoint`, `usb_bulk_setup_async`. `[C]`
- **Поток кадров:** `init_image_transfer`/`start_image_transfer`/`suspend`/`release`,
  исходник `data_transfer\imagetransfer.cpp`, `CreateThread`. `[C]`
- **Экспорты (выборка):** `read_sensor_data`, `write_sensor_data`,
  `set_cmos_read_address`, `write_cmos` (прямой доступ к регистрам CMOS камер!),
  `is_libusb_connected`, `send_data`, `get_data`, `get_sensor_data`,
  `save_cali_param`, `get_vision_version`, `get_soc_version`,
  `send_heartbeat_request`, `set_sdk_protocal`, `set_can_protocal`,
  `set_event_handler`, `reboot_soc`, `reboot_fastboot`, `upgrade_soc_version`,
  `enable_mvo`, `select_depth_image/greyscale/vga/imu/obstacle_distance/…`. `[C]`

**Отличие от DUML — твёрдо** `[C]`: отдельная DLL, нативный libusb0 bulk/interrupt,
собственный командный API на уровне экспортов, нигде нет маркеров DUML (`0x55`/SOF/frame).
**Обрамление не доказано** `[c]`: токены `cmd_id`/`check_sum`/`cmdid` есть только в
хост-приложении (`vc3`), не в самой `DJI_guidance.dll`, и строками байт-раскладку
(SOF, длина, порядок байт, ширина контрольной суммы) не подтвердить — нужен живой
захват. Метка «2.1.1.0 GuidanceSDK» — ярлык хост-приложения (`vc3`), а не версия
самой DLL (в дампе DLL версии нет). `[c]`

---

## 5. USB-топология и привязка драйверов

Два разных libusb-драйвера с **непересекающимися** наборами PID: `[C]`

**`DJI_BULK.inf`** — служба `libusb0_dji` (`libusb0_dji.sys`), GUID `…BACF4`.
Это наш «рабочий» драйвер (DUML/bulk):

| VID:PID | Интерфейсы | Имена |
|---|---|---|
| `2CA3:0020` | MI03, MI04, MI05, MI06, MI07 | MI03…MI07 |
| `2CA3:0022` | MI00, MI01, MI03–MI07 (MI02 объявлен, но не ставится — dangling) | 0022_MIxx |
| `2CA3:1021` | MI00 | — |
| `2CA3:1022` | MI02 | — |
| `2CA3:1023` | MI01 | — |

**`Vision_(Interface_3).inf`** — служба `libusb0` (plain, `libusb0.sys`), GUID `…BACF3`.
Это **vision-режим** (к нему цепляется GuidanceSDK):

| VID:PID | Интерфейс |
|---|---|
| `2CA3:001F` | MI03 |
| `2CA3:001D` | MI02 |
| `2CA3:3003` | MI03 |
| `2CA3:3180` | MI03 |
| `2756:0007` / `2756:0008` | MI03 (старый Guidance VID) |
| `2CA3:1010` / `2CA3:1020` | MI00 / MI01 |

**Ключ:** M4T в норме — `2CA3:0020`, где **все** MI03–MI07 держит `libusb0_dji`, а
vision-драйвер (`libusb0`) не биндит **ни одного** интерфейса PID 0020. `[C]`
Значит в нормальном режиме у M4T нет vision-libusb-устройства, к которому мог бы
прицепиться GuidanceSDK. `[i]` (Это вывод из непересекающихся PID-наборов +
подтверждённого в `docs/dji_assistant.md`/`docs/duml.md` факта «M4T = PID 0020,
MI03–MI07 bulk»; INF-файлы сами M4T/GuidanceSDK не называют, поэтому формально не
исключают, что борт мог бы переехать на vision-PID в каком-то спецрежиме.)

---

## 6. Процедура калибровки (реконструкция по verbs/events)

Порядок, собранный из команд и ответных событий: `[c]`

1. `vision_calibration_init(DEVICE, WIDTH, HEIGHT, SCREEN_WIDTH, SCREEN_HEIGHT, VERSION, CALIBRATION_TYPE)` → `init_ok` / `init_cali_status`
2. `config_screen_size` → `set_screen_size(VALUE)` (учёт физического размера/DPI экрана)
3. `set_cam_pair(INDEX)` — выбор пары камер
4. `enter_match_rect(COUNT)` → `match_rect_ok`
5. `enter_track(COUNT)` → `track_ok` / `track_x_ok` / `track_y_ok`
   (во время шагов оператора ведут подсказки `warn_aim_to_screen`,
   `warn_move_forward/backward`, `warn_rotate_left/right`, `warn_no_pattern`,
   `warn_obstruction`)
6. `start_calculation` → `set_calculation_progress` → `calculation_ok`
7. запись результата (см. §7)

Параллельно идёт поток картинок: движок отдаёт наложение паттерна
(`set_pattern_image_foreground/background(w, h, buf)` в DLL) и кадры камер, UI
получает их как события `camera_images`/`pattern_image_*`/`miniguide_image`.
Точная кодировка пикселей на проводе (base64-в-JSON vs бинарный WS-фрейм) и
частота кадров — открытый вопрос (§11).

---

## 7. Запись результата и гейтинг

**На борту** (строки vc2/vc3): `[C]`
`DJIVisionCalibrationWorker::calculateCheckPush` → `dump result` → `check result`
→ EEPROM (`save to eeprom success`) → стейджинг `/cali/dji_perception` → финал
`/factory_data/dji_perception` (+ `/calisummary`) → рестарт сервиса перцепции
`start_dji_perception.sh` / `vp_message_send_sync to start dji_perception`.

**В облако** (строки `DJIService.exe`): `[C]`
`POST /api/v2/assistant/calibration_info` (record_info, product, firmware_version,
app_type) — это и обслуживают WS-команды `upload_calibrate_info` /
`transfer_calibrate_result_file` сервиса `calibration_assist`.

**Два гейта** (оба должны пропустить, иначе функции/кнопки нет): `[C]`
1. **клиентский** — per-codename allowlist, зашитый прямо в `DJIVisionCalibration*.dll` (§8);
2. **серверный** — per-user whitelist из облака: `DJIServerApi::IsUserInVisionWhiteList`
   → `GET /api/v2/assistant/flags` возвращает `vision_flag` (`in whitelist, status is 1`).

---

## 8. Матрица поддерживаемых бортов

Allowlist — это кодовые имена, зашитые в каждую DLL. (Метод: отфильтровано по
префиксам DJI `wm/pm/ag/hg/wa`; наивный regex `[a-z]{2}\d{3}` даёт ложняки вроде
`cp140`=MSVCP140, `uv420`=YUV, `wd425`=/wd4251 и т.п. — исключены.) `[C]`

| DLL | Кодовые имена |
|---|---|
| **vc1** (legacy board/P4) | wm100, wm220, wm330/331/332/334/335/336, wm620, pm410, pm420 |
| **vc2** | wm160, wm162, wm170, wm230, wm231, wm232, wm240, wm245, wm246, wm330, pm320, **pm430**, pm431, ag600, ag601, hg330 |
| **vc3** (новейшая) | как vc2 + wm169, ag701, wa140, wa150, wa233, wa234; без pm431 |

(`tp1709`/`tp1813` в vc2/vc3 — тестовые паттерны/оснастка, не борта.)

**Про M-серию (критично для плана снятия протокола):** `[C]`
- **Matrice 30 = `pm430`** — есть в vc2 **и** vc3 (плюс `PM430 T1`, `pm431` в vc2).
  **M30 поддержан → это цель №1** для живого захвата.
- **Matrice 350 RTK — отсутствует** во всех трёх DLL в любом виде
  (`wm350/wm390/pm350/pm390` — ноль), даже в новейшей vc3. Этим тулчейном **не снять**.
- **Matrice 300 RTK — не подтверждён:** документированный `wm320` отсутствует; есть
  `pm320` (vc2+vc3), но в DLL нет человекочитаемых имён продуктов, так что
  `pm320 == M300 RTK` — правдоподобная, но **непроверенная** гипотеза `[c]`.

**M4T (`wa345`) — ноль попаданий во всех трёх DLL** `[C]`, при том что в vc3 есть
другие `wa`-коды (`wa140/150/233/234`) — то есть отсутствие именно `wa345`
значимо, а не «нет всего префикса».

---

## 9. Случай Matrice 4T (`wa345t`)

**Идентичность.** M4T = кодовое имя **`wa345t`** (M4E = `wa345e` `[c]`, инференс по
паре t/e и соседству в списке `DJIService.exe`). Все 23 модуля прошивки
`M4T_UAV_17.02.05.01` начинаются с `wa345t_`. `[C]` В JS M4T присутствует под этим
кодом (`Uav_wa345t`, `activeDeviceConfig.id=='wa345t'`); маркетинговых строк
«Matrice 4»/«M4T» в бандлах нет, отдельного бандла `wa345*.js` нет — M4T рендерится
общим `aircraft.js`. `[C]`

**Карта модулей прошивки** (теги из имён файлов; семантика — отраслевой контекст, `[c]`):

| ID | шт. | Тег(и) | Что это (кандидат) |
|---|---|---|---|
| 0000 | 1 | .cfg | манифест/конфиг (v17.02.0501) |
| 0103 | 2 | HK, IA640 | тепловизор 640×512 (две сборки) |
| 0105 / 0106 | 1/1 | — | LCPU / «Laser» |
| 0501 | 1 | — | — |
| 0802 | 1 | .ar0 | Ambarella SoC |
| 1005 / 1006 | 1/1 | GB95 / PA02 | — |
| 1100 | 3 | BA03WA345, WA345PTL, WA345GY0 | батарея (три сборки/вендора ячеек) |
| 1200 / 1202 | 2/2 | mc01, mc02 | контроллер(ы) |
| 1502 | 1 | .ar0 | второй Ambarella / CV-SoC |
| 2400–2403 | 4 | RD03 | перцепция ×4 (mmWave-радар, см. ниже) |
| 2405 | 1 | ld04 | LIDAR/дальномер |
| 2506 | 1 | lifnx17 | — |

**Почему калибровки нет — три ноги аргумента (с честной оценкой силы):**

1. **Нет в allowlist движка — сильно `[C]`.** `wa345`/`wa34` — ноль во всех трёх
   DLL, и DLL несут **позитивный** per-codename whitelist, в котором всей
   M4-семьи (`wa340/wa341/wa345e/wa345t`) нет. Остаточная оговорка — теоретический
   нелитеральный/числовой гейт, что whitelist делает маловероятным.
2. **Нет vision-USB-устройства — вывод `[i]`.** В норме M4T = `2CA3:0020`, все
   MI03–MI07 держит `libusb0_dji`, vision-драйвер `libusb0` не биндит ни одного
   PID 0020 → прицепиться GuidanceSDK не к чему. Это аргумент от отсутствия: INF
   не называют M4T и не исключают переезд на vision-PID в спецрежиме.
3. **Другая архитектура сенсоров — сильно `[C]`.** Обход препятствий M4T —
   **радар RD03 ×4** (модули 2400–2403; живой RE в `docs/vision.md` `[C]`:
   FRONT/LEFT/RIGHT/UP) **+ fisheye**, а не стерео-камеры. Оптическая калибровка
   по сетке кругов тут не применяется. Важно: M4T **не «без камер»** — у него есть
   fisheye (MIPI-CSI в CV-SoC) и тепловизор (0103 IA640); радарный именно **обход
   препятствий**, поэтому стерео-калибратор ему не нужен.

Причинность («because») — проектный **вывод** `[i]`: артефакты показывают, что M4T
нет в тулчейне и у него другой сенсор-стек (что согласуется с отсутствием
калибровки), но сам тулчейн причину не декларирует.

---

## 10. Как снять настоящий протокол (переориентированный план)

Чтобы получить реальный GuidanceSDK/vision-диалог — надо запустить калибровку на
**поддерживаемом** борте, где это штатная функция:

- **Цель №1 — Matrice 30 (`pm430`)**: подтверждённо в allowlist (vc2+vc3). `[C]`
  Запасные (коды в allowlist, маркетинг не подтверждён из DLL): `wm240/245/246`,
  `ag600/601/701`, `hg330`. M300 — только как кандидат (`pm320`), M350 — исключён.
- **Предусловия** (иначе UI/движок не стартует даже для allowlist-борта): `[i]`
  1. борт должен переехать на **vision-PID**, который держит plain-`libusb0`
     (`001F/001D/3003/3180/1010/1020` или `2756:0007/0008`) — `PID 0020` не
     подойдёт (его держит `libusb0_dji`);
  2. серверный whitelist (`IsUserInVisionWhiteList`) должен пропустить пользователя.
- **Транспорт захвата:** это **не MI04/DUML**, а libusb0 bulk/interrupt на
  vision-интерфейсе — USBPcap снимать нужно по нему (следим за сменой PID при
  входе в калибровку), протокол — GuidanceSDK, не DUML.
- **Что разрешит живой захват:** байт-раскладку обрамления (`cmd_id`/`check_sum`),
  кодировку потока картинок, логику выбора vc1/vc2/vc3 и фактический vision-PID.

> Напоминание по безопасности: калибровка — это **действие** (пишет EEPROM/
> `/factory_data`), запускать только на борте, где это штатно, и командами,
> которые выполняешь ты.

---

## 11. Открытые вопросы и уверенность

- **Логика выбора DLL.** Какой процесс грузит `DJIVisionCalibration{,2,3}.dll` и
  по какому правилу выбирает поколение под конкретный борт — строками не доказано.
  `VisionStarter{,2,3}.exe` существуют как файлы, но ссылок/`LoadLibrary` на них в
  дампах нет; роль «тонкий лаунчер → DLL» — гипотеза `[c]`.
- **`pm320` == M300 RTK?** `[c]` — нужен внешний список кодов или живой борт.
- **Обрамление GuidanceSDK** (`cmd_id`/`check_sum`, порядок байт) — не доказано `[c]`.
- **Кодировка потока картинок** (base64-в-JSON vs бинарный фрейм, fps) — открыто.
- **`wa345e` = M4E** `[c]` — инференс, прошивку M4E не смотрели.
- **Bind-порт сервера** — выведен из клиента (`:19871`/`:19870`), в бинарях сервера
  как литерал не найден `[i]`.

---

См. также [docs/vision.md](vision.md) — карта самой системы виженов M4T (что
достижимо по DUML, перцепция RD03, бинокуляр 1804), и
[docs/dji_assistant.md](dji_assistant.md) — USB-композит M4T и захваты Assistant.
