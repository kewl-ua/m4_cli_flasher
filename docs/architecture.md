[← README](../README.md)

# Как это работает

```mermaid
flowchart TB
    subgraph PC["ПК: Windows, Linux"]
        CLI["dji-duml<br/>cli.py"] --> FL["Flasher<br/>flasher.py"]
        CLI -- "open_client: открыть и переоткрыть USB" --> TR["transport.py<br/>поиск узла MI04"]
        CLI -. "--simulate" .-> SIM["sim.py<br/>эмулятор вместо USB"]
        FL --> PKG["package.py<br/>ZIP или dji_system.bin,<br/>манифест и MD5"]
        FL --> CMD["commands.py<br/>полезные нагрузки и разбор"]
        FL --> CL["DumlClient<br/>client.py"]
        CL --> FR["frame.py, crc.py<br/>кадры DUML v1"]
        CL -- "write / read" --> TR
        TR --> LW["libusb_win32.py<br/>libusb0_device.dll от DJI<br/>проверено на M4T"]
        TR -.-> PU["pyusb: libusb-1.0 на Linux<br/>чтение проверено на M4T, прошивка нет"]
    end
    LW --> DRV["драйвер libusb-win32"]
    PU -. "Linux: usbfs ядра, MI04" .-> R
    DRV -- "USB bulk, MI04<br/>OUT 0x04, IN 0x85" --> R
    subgraph DRONE["Matrice 4T"]
        R(("DUML"))
        R --> FC["0x1F<br/>отвечает версией дрона"]
        R --> UC["0x48<br/>центр обновления"]
        R --> OT["0x03, 0x28, 0x68 и другие<br/>модули и телеметрия"]
    end
```

- **Транспорт.** DUML v1 по USB bulk, интерфейс MI04 (OUT `0x04`, IN `0x85`),
  VID `2CA3` / PID `0020`. DJI ставит libusb-win32 как `libusb0_device.dll` со
  своей раскладкой структур (pyusb на ней падает), поэтому для неё есть своя
  ctypes-обвязка `dji_duml/libusb_win32.py`.
- **Процедура `upgrade-center`.** Хост `0x2A` говорит с модулем `0x48`
  (центр обновления): `00/83` → `00/84` (общий размер) → каждый файл пакета
  по манифесту кадрами `00/2A` (открыть, куски по 980 байт с окном 1250,
  потерянный дроном кусок — ещё раз по его отчёту о пропуске, MD5) →
  `00/85` (установка) → статусы `00/42` через одну-две
  перезагрузки дрона → Complete/Success → `00/4F` (установленная версия) и
  `00/41`. FTP не используется.
- **Гарантии.** Изменяющая команда отправляется ровно один раз; до записи
  сверяются модель, версии и MD5 каждого файла с манифестом; вердикт — только
  Complete от `0x48`; версия `00.00.0000` после перезагрузки означает «ещё не
  готов»; журнал JSONL пишет каждое решение. Подробно — в
  [duml.md](duml.md).

```mermaid
sequenceDiagram
    autonumber
    participant H as dji-duml (0x2A)
    participant F as 0x1F, версия дрона
    participant U as 0x48 центр обновления
    H->>F: 00/01 версия
    F-->>H: WA345T, текущая версия
    H->>U: 00/83, 00/84 (общий размер файлов)
    U-->>H: 00 07 00, 00
    loop 23 файла пакета
        H->>U: 00/2A открыть (имя, размер)
        H->>U: 00/2A куски по 980 байт, без ответа на каждый
        U-->>H: отчёт о принятых кусках, сам, раз в ~100 мс
        H->>U: 00/2A MD5 файла
    end
    H->>U: 00/85 установить
    U-->>H: 06
    U-->>H: 00/42 статусы раз в секунду
    Note over H,U: дрон сам перезагружается 1-2 раза, USB-адрес меняется,<br/>dji-duml переподключается и повторяет приветствие
    U-->>H: 00/42 Complete/Success
    H->>U: 00/4F, 00/41
    U-->>H: установленная версия
    H->>F: 00/01, пока версия не станет целевой
    F-->>H: 00.00.0000 = ещё не готов, затем целевая
```
