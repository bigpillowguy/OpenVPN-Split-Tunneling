# Результаты и границы проверки

26 сентября 2026, ветка `codex/first-stability-fixes`. Исходная точка ревью:
`5f6273d22d29233699175935b5b3516c84383100`. [REVIEW.md](REVIEW.md) описывает эту
точку, а [TODO.md](TODO.md) отслеживает исправления и оставшуюся приёмку.

## Локальные результаты

Проверено на Windows x64 с Rust 1.98.1 MSVC, .NET SDK 10.0.400 и Inno Setup 6.7.3.
Для Rust перед системным GNU toolchain поставлен каталог rustup:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
dotnet restore dotnet/VpnClient.Tests/VpnClient.Tests.csproj --locked-mode
dotnet test dotnet/VpnClient.Tests/VpnClient.Tests.csproj -c Release --nologo --no-restore
```

- **Rust: 76 тестов + 1 compile-only doctest**, 0 ошибок: 45 redirector,
  2 IPC, 29 vendored windivert. fmt и строгий workspace Clippy проходят.
- **.NET: 113 тестов**, 0 ошибок и предупреждений. Тесты компилируют фактические невизуальные
  production-исходники под net10.0-windows; UI отдельно собирается под net8.0.
- WPF Release build: 0 ошибок и предупреждений. Self-contained publish проходит.
- Оба NuGet lockfile сохранены; locked restore и publish/test с `--no-restore`
  проходят. CI использует те же проверки и отменяет устаревший запуск этой ветки.
- `installer/build.ps1` успешно вызван абсолютным путём из `%TEMP%` через Windows
  PowerShell 5.1. Собран `installer/Output/VpnClientSetup-1.0.1.exe`;
  версия UI и установщика согласована: 1.0.1.
- `installer/test-dependencies.ps1` проверяет features закреплённого подписанного
  MSI, валидный кеш, замену повреждённого кеша, отказ на битой загрузке и cleanup.
  Предупреждения о повреждённом кеше в этом тесте ожидаемы.
- `installer/test-native-staging.ps1` проверяет обновление устаревших DLL/SYS.
- `git diff --check` проходит.

## Что проверяют регрессии

| Изменения | Проверка |
| --- | --- |
| CORE-01/02/03 | `divert_tests.rs`: реальные smoltcp-интерфейсы в памяти, очередь upload глубиной 1, TCP TX-буфер 17 байт; сравнение всех байтов и порядка, FIN после дренирования, loopback request → EOF → response, обратный half-close. Большой случайный файл и RST через драйвер ещё не проверены. |
| CORE-04/05/06 | Текущий процесс через Win32 Resolver, подставленная старая generation, отзыв пути; wildcard BIND/CLOSE/rebind и поздний CLOSE старого endpoint. Реальное повторное использование PID и маршрутизация двух приложений требуют VM. |
| CORE-07/11/12/14 | Loopback TCP/UDP sockets освобождаются при отмене; пустые datagram продолжают обмен; смена target и Pending timeout удаляют flows; пакетные TCP flags и лимиты проверяются до создания нового flow. Массовый memory/handle soak остаётся открытым. |
| CORE-08/09 | Fake RouteApi проверяет поздний gateway, неудачное создание и повтор, восстановление удалённого маршрута, сохранение чужого default и точный cleanup собственного. Отдельный тест конструирует native Win32 row с LUID/index/next-hop и допустимыми полями. Нативные add/delete на машине не вызывались. |
| CORE-10/13 | `main.rs` проверяет, что ошибка IPC-компонента сигналит и дожидается blocking worker; штатный stop дожидается cleanup. Receive loops имеют timeout и передают ошибки координатору. Настоящий отказ WinDivert не инъецировался. |
| UI-02/11 | `SessionControllerTests.cs`: отмена handshake, последовательная замена, timeout/retry, сохранение ownership при ошибке stop, старые события и race CONNECTED/RECONNECTING. Используются fake sessions. |
| UI-04/08/10 | `ConfigTests.cs`: дубликаты путей, backup recovery, сохранение повреждённого файла, отказ перезаписи неисправимого config, неудачная замена, одновременные читатели и dev discovery. Транзитные IO errors допускаются; backend сохраняет последний валидный список. Disk-full/crash ещё требуют стенда. |
| UI-05/12 | Простые auth-user-pass/certificate-only profiles, whitespace и безопасная миграция host:port без обрезания IPv6. Во втором пакете добавлены quoting/includes/external dependencies; сложная auth-модель остаётся открытой. |
| SEC-01/02 | Уникальные сессионные секреты, чтение и удаление файла; management prompt без newline, отказ неверного пароля, отмена молчащего peer, escaping credentials. Реальный OpenVPN не запускался. |
| SEC-03/04/05/06 | Production policy server отключён; status ACL создаётся для текущего пользователя/SYSTEM. .NET валидирует диапазоны, адреса, дубликаты PID/paths и бюджеты snapshots. Stalled writer получает timeout. Проверка server PID реализована; межпользовательский и массовый IPC acceptance ещё не выполнены. |
| UI-01/09 | Job создаётся до children, kernel JOB_LIST назначается при CreateProcess, thread возобновляется после получения handles. Проверяется Windows argument quoting; запуск реальных children и отказ Job assignment остаются ручной/VM проверкой. |
| WinDivert recv_wait | Mock проверяет SOCKET/FLOW с нулём payload, сохранение metadata, malformed native lengths и native error. Три native named-pipe tests проверяют адрес OVERLAPPED, отмену только выбранного запроса, завершение до освобождения памяти и сохранение успешной гонки; драйвер не загружается. |

## Второй пакет: маршруты/DNS, импорт и адаптер

| Изменения | Проверка и ограничения |
| --- | --- |
| UI-03 | `RuntimeProfileTests.cs`: local redirect-gateway/redirect-private, обе IPv4 `/1`, IPv6 route, legacy dhcp-option и OpenVPN 2.7 dns исключаются; route-noexec/route-nopull обязательны. Managed pull filters стоят перед пользовательским accept-all; inline key и connection blocks сохранены, исходный файл не меняется. Для gateway metadata добавлен один неисполняемый route. Поведение PUSH_REPLY опирается на permission mask OpenVPN 2.7; реальный OpenVPN здесь не запускался. |
| UI-06 | `ProfileImportTests.cs`: десять типов зависимостей, пути с пробелами, бинарные файлы, inline blocks, root-relative nested configs, перенос исходной папки, совпадающие имена, отсутствующие файлы/циклы/лимиты. Частные ACL и rollback до Commit проверяются файловыми тестами. Device namespaces (включая slash aliases), ADS и drive-relative paths отклоняются. Delete сохраняет legacy/external/unowned files и каталог с неожиданными файлами. |
| CORE-15, .NET | `SessionBindingTests.cs`: native UP/ENV/CONNECTED metadata, чужой адаптер с тем же IP, GUID/index, malformed/duplicate environment, subnet mask не становится gateway. Lease не позволяет старым callback публиковать или удалять новую сессию. JSON содержит точный native FILETIME текущего процесса; ACL проверены. Windows adapter inventory только читается. |
| CORE-15, Rust | `session_binding/tests.rs`: схема JSON, PID generation/exe mismatch, GUID/index/up/IP, missing/malformed/oversized snapshot, новый sessionId при прежних IP/index. `vpn_state.rs`: gateway/LUID берутся из привязки даже без предварительных route rows; чужой gateway не считается готовым, cleanup точный. `divert_tests.rs`: смена generation удаляет старые flows. |
| Readiness/cleanup | UI принимает assigned IPv4 в состоянии Tentative для идентификации, Rust допускает только Preferred перед созданием маршрута/forwarding. Это сохраняет обработку DOWN без ожидания DAD внутри management-reader. Runtime-файл с inline keys удаляется вместе с session secrets и при очистке старых сессий; лог может остаться. |

DNS-модель: профиль и сервер не меняют настройки DNS; используется системный resolver.
Это не DNS-изоляция по приложениям и не гарантия разрешения VPN-only имён.
OpenVPN продолжает конфигурировать tunnel interface, а Windows может добавлять
connected routes. Нативные операции добавления/удаления маршрутов в тестах заменены
fake RouteApi. Настоящие DCO/TAP, DHCP/adaptive timing, DNS и внешний IP остаются в QA-02.

Политика сверена с upstream
[OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html),
[pull_permission_mask/do_open_tun](https://github.com/OpenVPN/openvpn/blob/v2.7.4/src/openvpn/init.c)
и [parser](https://github.com/OpenVPN/openvpn/blob/v2.7.4/src/openvpn/options_parse.c).
`route-nopull` исключает OPT_P_ROUTE/OPT_P_DHCPDNS; route-gateway остаётся доступным.
Pull filters сами по себе не являются защитой от вариантов whitespace в pushed options.

## Исправления, найденные при проверке этого пакета

- Первая установка без `config.json` должна запускать backend с пустой policy;
  восстановленный backup сохраняется до запуска backend.
- [`InitializeIpForwardEntry`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeipforwardentry)
  оставляет часть полей недопустимыми: native row явно задаёт SitePrefixLength,
  Protocol, Metric и flags.
- Завершение `ConnectAsync` не должно перезаписывать более свежий RECONNECTING.
  Для этой гонки добавлена регрессия.
- Build проверяет фактический Cargo compiler artifact, чтобы внешний target-dir
  не привёл к упаковке старого файла из `target/release`.
- GitHub Actions первого пакета выявил расхождение implicit ILLink dependency:
  latestPatch выбирал новый SDK с 8.0.31 вместо зафиксированного 8.0.30. `global.json`
  теперь требует ровно SDK 10.0.400; обновление SDK и lockfile выполняется вместе.

## Что обязательно проверить перед стабильным релизом

### Инцидент на установленной 1.0.0 и патч 1.0.1

Пользователь установил 1.0.0 на текущем ПК и получил `VPN connected — routing
unavailable`. При чтении состояния OpenVPN работал, redirector отсутствовал,
WinDivert был загружен; установленный backend совпадал с предыдущим build.
Привязка сессии указывала на действующий DCO adapter и совпадающие IP/index/GUID.
Чтение списка адаптеров установленным redirector и компиляция фильтров DLL
проходили. Это не проверка передачи данных через capture.

Найден дефект в `windivert 0.7.0-beta.4`: `recv_wait` превращал успешный приём
SOCKET event с нулём payload bytes в `NoData`. SOCKET/FLOW содержат metadata,
а не IP packet; это описано в
[WinDivertRecv](https://reqrypt.org/windivert-doc.html#divert_recv) и подтверждается
завершением read с `read_len = 0` в
[WinDivert 2.2.2 driver](https://github.com/basil00/WinDivert/blob/v2.2.2/sys/windivert.c).
Observer считал этот результат постоянной ошибкой и останавливал backend.
Изначальные тесты не покрывали контракт этой зависимости — успешная сборка и
проверки обработки пакетов не обнаружили такой ранний выход.

В workspace включена локальная копия wrapper с upstream provenance и лицензией.
Патч принимает нулевой payload для metadata-only events и проверяет native lengths.
Отмена timeout теперь использует `CancelIoEx` для конкретного запроса и ждёт
окончательного `GetOverlappedResult`, прежде чем освобождать OVERLAPPED/buffers.
OVERLAPPED хранится по стабильному адресу; успешно завершившийся запрос при
гонке с timeout возвращается вызывающему коду.

Backend сохраняет цепочки ошибок и panic/backtrace в частный `redirector.log`
(2 MiB + один архив `.1`). События сокетов пишутся только при DEBUG. UI наблюдает
выход процесса, показывает код/путь и не объявляет мёртвый backend готовым.
Файловые регрессии проверяют удаление session.json с сохранением открытого лога
и cleanup каталога без логов. Native child с CREATE_NO_WINDOW проверяет ожидание
настоящего named event и запись panic без драйвера; предполагаемый отказ console
handler на этом ПК не воспроизведён и не считается причиной инцидента.

Установщик 1.0.1 предназначен для повторной проверки на ПК пользователя. До
обновления и нового подключения нельзя считать восстановление маршрутизации
подтверждённым. Во время диагностики агент не отключал VPN, не запускал capture
и не менял системные маршруты.

### Оставшаяся приёмка

1. Чистые Windows 10/11 x64: установка, обновление, удаление, MSI errors/reboot,
   соседний независимый OpenVPN и занятый драйвер.
2. Настоящий VPN: большие передачи с контрольной суммой, низкие скорости, оба
   порядка FIN/RST, port/PID reuse, тысячи UDP flows, переходы target и shutdown.
3. Job/crash/forced kill, отказ драйвера, spoofed pipe, другой Windows user,
   много медленных IPC-клиентов, отсутствие доступа к файлам и заполненный диск.
4. Приёмка UI-03/06/CORE-15: local redirect-gateway + pushed `/1`/DNS, внешний IP
   listed/unlisted apps, системный DNS/DoH, профиль с настоящими сертификатами после
   переноса исходной папки, два VPN, same-IP reconnect, DCO/TAP и delayed readiness.
5. ENG/PROD: IPv6, полный TCP tuple, reinjection, MTU/fragmentation и fail-open.

Агент выполнял сборку без запуска установщика. Установку 1.0.0 и подключение
выполнил пользователь; read-only диагностика инцидента описана выше. Во время
автоматических проверок VPN/WinDivert capture и системные маршруты не менялись.
GitHub Actions на commit `63df232` прошёл после закрепления SDK:
[run 36237661483](https://github.com/bigpillowguy/OpenVPN-Split-Tunneling/actions/runs/36237661483).
Результат CI для нового пакета учитывается отдельно от этого запуска и локальных тестов.
