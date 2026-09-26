# Результаты и границы проверки

26 сентября 2026, ветка `codex/first-stability-fixes`. Исходная точка ревью:
`5f6273d22d29233699175935b5b3516c84383100`. [REVIEW.md](REVIEW.md) описывает эту
точку, а [TODO.md](TODO.md) отслеживает исправления и оставшуюся приёмку.

Актуальные результаты 1.2.0 находятся в последнем разделе. Предшествующие разделы
сохраняют проверки пакета 1.0.x и исходные ограничения приёмки.

## Локальные результаты 1.0.x

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

## Windows VPN Platform и клиент 1.2.0

UI сохраняет обычный запуск приложений и явно сообщает, что per-app VPN DNS
пока не включён. DNS-метаданные OpenVPN и отдельный opt-in Rust transport
сохранены для будущей интеграции. UI не запускает этот DNS broker.

Проверено локально после изменения текущего дерева:

- .NET locked restore, 153 теста и Release WPF build: успешно, без предупреждений.
- Rust formatting, строгий workspace clippy, 90 тестов включая doctest: успешно.
- Регрессия установщика: занятый старый компонент вызывает отказ без загрузки
  его кода; проверены отсутствующий файл, удержание эксклюзивного write handle
  до удаления и запрет новых читателей. Inno Setup compile-check прошёл.
- Release redirector, self-contained WPF publish и установщик 1.2.0 собраны.
  Пакет: 80 095 778 байт, SHA-256
  `8C9244E0C73C0CEA852199A7478B55C6C1D0A3D230212B856A545341F66AA3F6`.
  Установщик не запускался. Native staging и MSI/cache integrity tests прошли.
- Windows VPN Platform имеет отдельные offline проверки и unsigned Appx.
  Прошли 52 проверки DNS codec, 51 проверка реальных WinRT profile objects,
  локальная COM-фабрика и MakeAppx (7 файлов пакета). Их ограничения записаны в
  [BUILD-EVIDENCE.md](research/VpnPlatform/BUILD-EVIDENCE.md).

Регистрация пакета и живое разделение DNS-контекстов ещё требуют новой VM.
Никакой результат сборки не заменяет сетевую матрицу из
[VM-RUNBOOK.md](research/VpnPlatform/VM-RUNBOOK.md).

Полный GitHub Actions workflow для `317b0f2` завершился успешно:
[run 36258450724](https://github.com/bigpillowguy/OpenVPN-Split-Tunneling/actions/runs/36258450724).
Помимо тестов Rust, .NET и offline-проверок платформы, CI собрал установщик
и выполнил проверки native staging, MSI/cache integrity и удаления прежних компонентов.

## Экспериментальный split DNS — 1.3.0

Реализован резервный PIA-подход собственной реализацией: временная заглушка
Dnscache, независимая служба восстановления, журнал до изменения реестра,
перенаправление DNS/53 выбранных EXE через DNS текущего VPN. Режим по умолчанию
выключен; Windows VPN Platform сохранён как отложенное исследование.

Проверено локально:

- Workspace Rust fmt и строгий clippy: успешно. 108 тестов, включая 76 redirector,
  2 IPC, 29 vendored wrapper и 1 doctest: успешно, без ignored/failed.
- 171 тест .NET клиента и WPF Release build: успешно, без предупреждений.
- 49 тестов DNS guard: аварийные границы, отказ записи журнала, сохранение чужих
  изменений, владелец/lease, maintenance barrier и настройка restart policy.
  Проверки используют подставную платформу и не вызывают SCM/изменение реестра.
- Взаимный review исправил трактовку ошибки IPv4/IPv6 socket table как пустой
  таблицы, доставку запоздалого ответа после смены владельца endpoint, подтверждение
  старой завершённой lease, недонастроенную recovery policy после прерванной
  установки службы и блокирование rollback при повторном отказе записи журнала.
- Полный `installer/build.ps1`: release redirector, locked restore, self-contained
  UI и отдельный self-contained каталог guard, Inno Setup 6.7.3 — успешно.
  Установщик 1.3.0: 103 725 404 байт, SHA-256
  `D9129DAC5A6163F8233728B3AE1EACF4F98ED6937D066373C6F2F36579B55BE3`.
- Native staging, MSI/cache integrity и mapped-image/legacy retirement regression:
  успешно. Установщик собран, но не запускался.
- Read-only проверка текущей Windows показала исходный Dnscache Type `0x10`,
  NetworkService, Microsoft-signed System32 svchost. Исходные `0x10` и `0x20`
  сохраняются; для общего типа дополнительно требуется отдельный `-s Dnscache`.
  Это наблюдение не заменяет полную privileged preflight и живую активацию.

Пользователь установил промежуточную 1.3.0 и включил режим во время разработки:
UI сообщил `DNS activation could not be confirmed. service_timeout` при
подключённом VPN. Read-only журнал SCM показывает автоперезапуск Dnscache через
1000 ms и отказ guardian примерно через 10 секунд после завершения исходного
процесса. Повторная попытка дала ту же последовательность. После recovery
Dnscache работает в `svchost.exe`, guardian остановлена с кодом 0.
Это свидетельствует о гонке ожидания STOPPED с автозапуском службы;
не является успешной приёмкой DNS-изоляции.

Не пройдены полная приёмка подмены/восстановления Dnscache, crash/reboot, действие
maintenance при настоящем обновлении/удалении, происхождение DNS из обычного
resolver и Chrome, packet capture на физическом/VPN интерфейсах. Агент не запускал
системные изменения или WinDivert capture; живую попытку выполнил пользователь.

Ограничения: глобальный кеш Dnscache затрагивается; DoH/DoT не переписываются;
выбранный IPv6/loopback DNS, неопределённый владелец и неприписываемые фрагменты
блокируются. Последнее может повлиять и на невыбранные приложения. DNS-01
остаётся открытой до сетевой и аварийной приёмки из [DNS-DESIGN.md](DNS-DESIGN.md).

### Исправление тайм-аута службы — 1.3.1

Ожидание обязательного STOPPED заменено проверкой нужного конечного состояния:
принимается уже работающий экземпляр заглушки с точным lease либо восстановленный
Microsoft svchost. Устаревший PID SCM и процесс, завершившийся во время проверки,
не считаются подтверждением идентичности. Восстановление сначала использует
штатный STOP проверенной заглушки; если ACL службы запрещает STOP, допускается
завершение только её удерживаемого процесса. Неизвестные процессы не завершаются.

Добавлены точные причины этапов (`stub_start_timeout`, `original_restore_timeout`),
регрессии пропущенного STOPPED, START/STOP_PENDING, прямого автоперезапуска,
устаревшего PID и повторной проверки владельца перед остановкой. Guard: 62 теста
прошли, locked restore и self-contained publish успешны. Независимый review
не оставил блокирующих замечаний. Остальные 171 тест клиента и 108 тестов Rust
относятся к неизменённой логике этих компонентов; версия UI изменена на 1.3.1.

Пользователь установил 1.3.1: активация дошла до состояния Active без прежнего
тайм-аута, но Chrome получил `DNS_PROBE_FINISHED_NXDOMAIN`. Пользователь также
сообщил об общем отказе DNS; отдельно от Chrome масштаб ещё не подтверждён.
После выключения экспериментального режима исходная Dnscache работает,
guardian остановлена, обычное разрешение имён восстановилось.

Read-only диагностика с активным VPN и выключенным split DNS: UDP socket,
привязанный к IPv4 и interface index текущего туннеля, получил от DNS провайдера
успешные A-ответы для `browserleaks.com` и `example.com`. AAAA и HTTPS/65 для
`browserleaks.com` вернули NOERROR/NODATA с SOA; проверены запросы с EDNS/без него.
Это подтверждает доступность провайдера по UDP, но не доставку ответа выбранному
приложению. Браузерный NXDOMAIN не доказывает DNS RCODE от провайдера. Старые
счётчики также включали mDNS и учитывали ответ до успешной инъекции.

GitHub Actions для `e1c9bbb` прошёл полностью:
[run 36263321337](https://github.com/bigpillowguy/OpenVPN-Split-Tunneling/actions/runs/36263321337).
Успех CI не устраняет наблюдаемый сетевой отказ. DNS-01 остаётся открытой.
Полный `installer/build.ps1` для 1.3.1 прошёл. Установщик: 103 738 920 байт,
SHA-256 `4FD54571711F07F791E4E4BCA66F5E15B9615DF6922056901CC622A525208AA0`.
Установщик агентом не запускался.

### Доставка DNS и управление фильтром — 1.3.2

Найдены два дефекта: DNS-ответы вводились как outbound, а DNS-блокировки
работали весь срок жизни backend с `--split-dns`, независимо от состояния guard.
Второй дефект мог влиять на невыбранные приложения после отказа активации или
восстановления Dnscache. Эти дефекты подтверждены исходниками; их исправление
ещё не является доказательством причины всех наблюдавшихся отказов на ПК.

DNS UDP/TCP replies теперь используют inbound с захваченными IfIdx/SubIfIdx.
Свежая проверка владельца endpoint и lease перед доставкой сохранена. UDP IN
учитывается после успешного WinDivertSend; получение приложением не подтверждено.
Диагностика различает owner lookup, QTYPE, provider endpoint, RCODE/TC/число ответов,
transport error и injection result. QNAME/RDATA и содержимое пакетов не пишутся.
Новые события ограничены 32 записями каждой категории за 10 секунд; общий журнал
сохраняет прежнюю ротацию. `Dropped` не равен числу всех неудачных DNS-запросов.

Private control-файл вводит отдельную lease фильтра с монотонным revision,
PID/FILETIME обоих процессов и session/generation VPN. Начальное состояние
неактивно. До Acquire нужен свежий arm ACK; после подтверждения восстановления
guard нужен disarm ACK либо подтверждённая смерть удерживаемого backend.
Неопределённый результат arm не допускает Acquire; неподтверждённый restore
сохраняет фильтр. Старые команды/ACK не меняют новую lease. Переход очищает
DNS-потоки, их workers, smoltcp sockets и очереди; асинхронные permits связаны
с revision. Повреждение control-файла не снимает уже работающий фильтр.

Локальные проверки финального кода:

- Rust fmt и строгий workspace clippy: успешно. 123 теста (91 redirector,
  2 IPC, 29 vendor, 1 doctest) прошли, без failed/ignored.
- 183 теста клиента и WPF Release build: успешно, без предупреждений.
- Общая JSON fixture проверяет C# writer и Rust parser, включая GUID и целые
  FILETIME/revision выше границы точности IEEE-754. Проверены stale/replayed ACK,
  смена backend/VPN, отказ arm/restore/disarm, очистка очередей до ACK и обычный
  TCP/53 при неактивном фильтре. Подставные контроллеры не меняют службы.
- Независимое ревью доставки и lifecycle не оставило блокирующих замечаний.
  Код guard не менялся относительно 1.3.1 с 62 успешно пройденными тестами.
- Полный `installer/build.ps1`, native staging, MSI/cache integrity и legacy
  component retirement regression прошли. Установщик 1.3.2: 103 749 262 байт,
  SHA-256 `89244FB28FCB9EEB8BC4B7C9B28F59F49AC908B9AF7313E0C7CA1DC98417136C`.
  Установщик агентом не запускался.

Живая повторная проверка доставки DNS, влияния на невыбранные приложения и
отсутствия утечки ещё не выполнена. Во время этих проверок агент не включал
экспериментальный режим и не менял DNS, маршруты или службы хоста.
