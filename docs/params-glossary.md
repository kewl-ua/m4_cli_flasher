[← README](../README.md)

# Справка по параметрам полётного контроллера

Эта справка объясняет **схему имён** таблицы 0 и смысл **ключевых семейств**
параметров, которые читает `params` (см. [«Параметры полётного
контроллера: `params`»](reading.md#параметры-полётного-контроллера-params)). Имена —
это собственные символы прошивки FC (C-пути структур), поэтому большинство
говорят сами за себя; ниже — только их группировка и то, что подтверждено
источниками. Полный список (907 параметров на 17.02.0501) не приводится:
он **меняется с версией прошивки** (1562/905 на 16.01.0006, 1563/907 на
17.02.0501), и индексы при этом сдвигаются — поэтому справка описывает
**семейства по именам, а не по индексам**.

**Условные пометки:** `[public]` — смысл задокументирован внешним
публичным источником (dji-firmware-tools, гайды сообщества, DJI SDK,
стандартная теория управления) **или** проверен на железе в этом проекте;
`[вывод]` — смысл выведен из имени и общей практики, пер-параметрического
внешнего источника нет.

## Соглашение об именах

- **`g_config.*` против `g_status.*`.** `g_config.*` — **настройки**
  (постоянные: пределы, усиления режимов, флаги-включатели); их правят DJI
  Assistant и сторонние инструменты, диапазон навязывает сам FC.
  `g_status.*` — **живая телеметрия и состояние** (здоровье датчиков,
  калибровка, статистика); фактически только для чтения. Отдельная ветка
  `g_cfg_debug.*` — инженерные/отладочные переопределения. Надёжный признак
  «настройка или показание» — именно префикс плюс шаблон «пределы `[0..0]`,
  всегда changed» у живых показаний (атрибут-байт на запись в прошивке не
  разобран — по нему категорично о записываемости судить нельзя).
- **Псевдоним `короткое|полный.путь`.** Один индекс часто возвращается под
  **двумя** именами через `|`: короткий мнемонический алиас и полный
  точечный путь структуры — это одно и то же, не два параметра
  (напр. `forearm_led_ctrl|g_config.misc_cfg.forearm_lamp_ctrl`,
  `tripod_func_enabled|g_config.mode_tripod_en_cfg.tripod_func_enabled`).
  Прошивка хранит оба указателя (`nameptr` + `aliasptr`).
- **Группы `*_cfg`.** Вложенные под-структуры собирают связанные настройки:
  `misc_cfg`, `mvo_cfg`, `novice_cfg`, `flying_limit`, `go_home`,
  `avoid_obstacle_limit_cfg`, `voltage`/`voltage2`, `rc_cfg`, `gps_cfg`,
  `fdi_switch`/`fdi_sensor[N]` и т. д. `mode_<имя>_cfg` — один профиль
  управления на каждый лётный режим.
- **Индексы датчиков.** Избыточные датчики нумеруются суффиксом:
  `imu0`/`imu1`/`imu2` (три IMU), `compass0` (магнитометр),
  `gps0`/`gps1`/`gps2`; поля-массивы — `q[0..3]`, `temperature[0..2]`,
  `fdi_sensor[0..2]`.
- **Токены в именах.** `_en`/`_enable`/`_enabled` — булев флаг-включатель;
  `fscap_*` — признак поддержки функции/возможности (часто в паре с
  `_app_enable` — «приложению разрешено задавать»; раскрытие `fscap` —
  вывод); `*_fdi_open_*` — флаг одного монитора неисправности одного
  датчика; `sim_`/`SIM_`/`simulator_` — входы встроенного симулятора.

## Ключевые семейства

| Семейство (примеры имён) | Что это | Источник |
|---|---|---|
| `g_config.flying_limit.*` (`max_height`, `max_radius`, `radius_limit_enabled`, `roof_limit_enable`) | Геозабор полётной оболочки: потолок высоты, радиус от точки взлёта, включение этих лимитов. Классическая «разблокировка высоты». | `[public]` |
| `g_config.airport_limit_cfg.*`, `support_unlimit_height`, `support_offline_areaid_unlock` | Геозабор аэропортов/зон (радиус поиска, отключение лимитов), флаги GEO-разблокировки. **NFZ-полигоны как таковые — отдельная жёстко зашитая таблица**, не эти параметры. | `[public]` |
| `ce_country_type`, `ce_regulatory_level`, `EU_CE_Reg_*` (`RID_Enable`, `GeoSense_Enable`, `120Height_Enable`, `MxSpeedLimit_Enable`, `LowSpeedMode_Enable`) | Региональный/регуляторный профиль: какие требования ЕС (класс CE, Remote ID, GeoSense, лимит 120 м, ограничения скорости) FC навязывает. | `[public]` |
| `g_config.avoid_obstacle_limit_cfg.*` (`avoid_obstacle_enable`, `a_dec_max`, `v_fwd_max`, `v_bck_max`, `safe_dis`) | Ядро обхода препятствий: мастер-включатель, макс. торможение, пределы скорости у препятствия, страховочная дистанция. | `[public]` (подтверждено в `docs/vision.md`) |
| `user_avoid_enable`, `go_home.avoid_enable`, `mvo_cfg.mvo_func_en` | Пользовательский мастер-тумблер обхода; обход во время возврата домой; включение вижн-позиционирования (MVO). | `[public]` (подтверждено в `docs/vision.md`) |
| `user_all/down/back_avoid_enable`, `enable_horizontal_obstacle_avoidance`, `omni_avoid_fov`, `*_avoid_min_dis_m`, `using_perception_*_avoid_info` | Пер-направленные тумблеры (низ/зад/омни), поле зрения и мин. дистанции сенсинга, выбор источника данных перцепции (mmWave/вижн). | `[вывод]` |
| `vps_func_en`, `fscap_vps_app_enable`, `enable_downward_vision_position_and_avoidance`, `fscap_mvo_func_able` | Нижнее вижн-позиционирование (VPS): удержание позиции и точная посадка без GPS; гейты возможности/разрешения приложения. Какое направление (вперёд/вниз) закрывает MVO против VPS на M4T — не установлено твёрдо. | `[вывод]` |
| `g_config.go_home.*` (`fixed_go_home_altitude\|go_home_height`, `go_home_heading`, `go_home_finish_radius`, `force_ascending_align_enable`) | Поведение возврата домой (RTH): высота набора, курс носа, радиус завершения, выравнивание перед полётом. | `[вывод]` (сам RTH документирован DJI; `go_home.avoid_enable` — `[public]`) |
| `rc_lost_action`, `g_config.fail_safe.*`, `sdr_lost_prevent_*` | Что делать при потере радиосвязи (SDR = радиолинк DJI): зависание / посадка / RTH и запреты взлёта без линка. | `[вывод]` (поведение failsafe документировано DJI) |
| `g_config.mode_normal_cfg.*`, `mode_sport_cfg.*`, `mode_gentle_cfg.*`, `mode_tripod_cfg.*`, `mode_atti_normal_cfg.*`; `tripod_func_enabled`, `novice_func_enabled` | Профили управления на каждый режим (масштаб стиков, пределы крена/тангажа, скорости вверх/вниз, экспонента); мастер-включатели Tripod и Novice. | `[вывод]` (режимы документированы; поля выведены, скорости косвенно подтверждает гайд сообщества) |
| `imu0/1/2.*` (`q[0..3]`, `acc_*`, `gyro_*`, `temperature[0..2]`, `press_alti`, `gps_svn`), `compass0.*`, `device_gyr_acc.busy.*`, `imu_cali_*`/`imu_app_temp_cali.*` | Живое состояние IMU/компаса (не настройки) и бухгалтерия калибровки (счётчики, шаги, температуры). **`imu0.lati`/`imu0.longti` — координаты борта в радианах, не публиковать.** | `[вывод]` (стандартная телеметрия DJI) |
| `*_fdi_open_*` (`acc_`, `gyr_`, `baro_`, `compass_`, `gps_`…incl. `jam_status`/`spoof_status`), `g_config.fdi_sensor[0..2].*`, `fdi_switch.*` | FDI = обнаружение и изоляция отказов: по флагу на датчик × тип отказа (обрыв, выход за диапазон, рассогласование; для GPS — глушение/спуфинг). Решает, когда перестать доверять датчику. | `[вывод]` (FDI — стандартная практика UAV) |
| `g_config.voltage.*`, `g_config.voltage2.*` (`level_1/2_voltage`, `level_1/2_function`), `dji_bat_level_1/2`, `battery_status`, `bat_power_protect_inhibit_takeoff_thres` | Пороги умной батареи и защита при низком заряде: предупреждение (ур.1) и критический (ур.2) с действием (RTH/посадка), запрет взлёта. | `[public]` |
| `forearm_led_ctrl\|g_config.misc_cfg.forearm_lamp_ctrl` | Управление лампами на лучах = **навигационные огни** борта. Запись этого параметра зажгла огни на живом M4T. | `[public]` (проверено на железе в этом проекте) |
| `ext_led_ctrl`, `param_single/hidden_ledctrl_enable/exist`, `led_test_item_param` | Подсистема LED: 32-битное поле внешних LED (раскладка бит неизвестна), флаги наличия/разрешения одиночного и скрытого LED-управления, селектор заводского LED-теста. | `[вывод]` |
| `gps_enable`, `g_config.gps_cfg.*`, `gnss_source_mode`, `gnss_assist_online/offline_enable`, `rtk_*` (`rtk_power_ctrl`, `rtk_fix_last`) | Конфигурация GNSS/RTK: включение, выбор созвездия/источника, ассистированный GPS (эфемериды), источник и удержание RTK-фикса. | `[вывод]` (функции позиционирования документированы, пер-поле выведено) |
| `rc_sbus_*` (`0_A_roll`, `1_E_pitch`, `2_T_throttle`, `3_R_yaw`, функц. переключатели, `failsafe`/`frame_lost`/`packet_cnt`), `g_config.rc_cfg.*`, `dead_zone`, `rc_throttle_sensitivity` | Карта каналов S.Bus (AETR + переключатели) и живой статус линка; настройки чувствительности стиков, мёртвой зоны, аварийного стопа моторов. | `[public]` для S.Bus-схемы; `rc_cfg.*` — `[вывод]` |
| `sweep_*` (`sweep_test_flag`, `sweep_start_f_A`/`stop_f_A`, `sweep_amp_A`, `sweep_prbs_*`), `auto_tuning_*` (`tgt_fcross`, `*_phase`), `av_notch_{x,y,z}N_*` (`fn`, `bw`, `gn`) | Системная идентификация и настройка контура управления: инжекция чирпа/PRBS для измерения АЧХ, авто-тюнинг по целевой частоте среза, режекторные/ФНЧ-фильтры контура угловой скорости. **Заводской/инженерный инструмент, не полётная функция.** | `[public]` для метода (ArduPilot SystemID, PX4 autotune); DJI-специфика — `[вывод]` |
| `sim_*`/`SIM_*`/`simulator_*` (`simulator_gps_svn/hdop/pdop`, `SIM_FLY_LIMIT_ENABLE`, `sim_initial_altitude`) | Входы встроенного симулятора полёта DJI Assistant: фейковые спутники/HDOP, сим-смещения, применяются ли лимиты в симуляторе. Не реальный полёт. | `[вывод]` (симулятор — документированная функция) |
| `g_status.user_info.statistical_info[_last/_new].*` (`total_distance`, `total_motor_start_time`, `total_powerup_times`, `total_fly_times`) | Счётчики налёта (одометр): суммарное расстояние, время моторов, число включений и полётов. Только чтение; **значения не публиковать.** | `[вывод]` (самоописательные, префикс `g_status`) |

## Как читать и менять

- **Чтение — `params` (только чтение).** Читает всю таблицу 0 через
  `03/E0`→`E1`→`E2`, ничего не меняет и не требует unlock. Фильтры:
  `--name ТЕКСТ` (имена с подстрокой), `--changed` (не по умолчанию),
  `--json`, `--capture` (из USB-захвата, без дрона). Детали —
  [«Параметры полётного контроллера: `params`»](reading.md#параметры-полётного-контроллера-params).
- **Запись — `set-param` (один параметр, безопасно).** Единственная
  команда, шлющая `03/E3`. Пишет **ровно один** параметр: валидирует по
  типу/размеру/пределам из `03/E1`, сверяет текущее с обязательным
  `--expected` (защита от устаревшего предположения), пишет один раз,
  читает обратно и печатает команду `undo`. **По умолчанию dry-run** —
  без `--yes` ничего меняющего не отправляется; `--capture` только
  проверяет по захвату. Детали —
  [«Запись параметра (`set-param`)»](reading.md#запись-параметра-set-param).
- **Осторожно со значениями.** В выводе и JSON есть координаты борта
  (`imu0.lati`/`imu0.longti`, радианы), налёт и регион, а в `probe`/
  `serial-scan` — серийники: убирайте их перед отправкой. Состав таблицы и
  индексы зависят от версии прошивки — сверяйте по имени, не по индексу.

## Источники

- dji-firmware-tools (o-gs/Mefistotelis): `dji_flyc_param_ed.py` (извлекает
  массив `flyc_param_infos` — те же `g_config.*`/`g_status.*` с типами и
  пределами из прошивки), `comm_dissector/wireshark/dji-dumlv1-flyc.lua`
  (именует команды набора `0x03` `0xE0`–`0xE9` и `0xDF` unlock),
  `dji_flyc_nofly_ed.py` (отдельная таблица NFZ) —
  https://github.com/o-gs/dji-firmware-tools
- hdnes/pyduml — https://github.com/hdnes/pyduml (только прошивка, набор
  `0x40`; параметры не пишет — для контекста)
- Гайд сообщества по FC-хакам (Inspire 1): `flying_limit.max_height`,
  `voltage2.level_*`, `control.*` скорости —
  https://greyarro.ws/t/dji-inspire-1-hacks-how-to-remove-nfz-height-limits-modify-flight-parameters-and-increase-maximum-speeds/4368
- Phantom 3 flight controller parameters —
  https://phantompilots.com/threads/phantom-3-flight-controller-parameters.105884/page-4
- mavicpilots (VPS / developer tools) —
  https://mavicpilots.com/threads/vision-position-sensor-help.25857/
- heliguy, «Drone obstacle avoidance explained» —
  https://www.heliguy.com/blogs/posts/drone-obstacle-avoidance-explained/
- ArduPilot SystemID — https://ardupilot.org/copter/docs/common-systemid-mode.html ;
  PX4 autotune — https://docs.px4.io/main/en/config/autotune_fw.html
  (sweep/PRBS/notch/autotune как стандартные методы)
- DJI Mobile SDK (`DJIFlightLimitation`) и DJI Assistant 2 (Enterprise) —
  официальная семантика лимитов, VPS, RTH, режимов и симулятора
- В этом репозитории: `docs/vision.md` (подтверждённые `[C]` obstacle/
  vision-гейты), раздел [«Запись параметра»](reading.md#запись-параметра-set-param)
  (железно-проверенный `forearm_led_ctrl`), `dji_duml/params.py`,
  `dji_duml/writes.py`, `dji_duml/roles.py`
