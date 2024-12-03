# Seijaku C2 Writeup

## 题面

是溯源反制题目。只给出流量包，见 [capture.pcap](./challenge/capture.pcap)。

## Writeup

下载流量包发现一个下载请求，打开对应网址发现是题目环境，根据 Referer 头可以找到 API 文档页面。

![image](https://github.com/user-attachments/assets/4bd2c031-b6fe-4121-9a87-e91d12c21970)

但是由于题目携带的请求 Token 已经过期，所以目前什么都做不了，于是下载响应文件开逆。

发现是 UPX 壳，小脱一手然后拖进 IDA 分析，瞪眼法可知有个 RC4 和一个 CRC64。

![image](https://github.com/user-attachments/assets/b5c5b948-868f-4b97-9190-ec8b39824d46)

简单调调或者也靠瞪眼法应该就能看出来密钥具体是怎么计算的，这里直接贴相关源码了：

https://github.com/mix-archive/SeijakuC2/blob/8fa6abc3c161d4d9dfea540995fc9ce1377b6f20/src/seijaku/client/client.c#L230-L249

大概就是用给定的固定密钥 + 当前 Unix 秒级时间戳进行 CRC64，把这个值发送给 C2 服务器，然后和固定密钥进行循环异或作为本次 RC4 加密密钥。

> [!NOTE]
> 这个算法是从 VMessMD5 那里得到启发的，不过 RC4 和这个做法都很不安全，容易受到主动探测攻击，~~如果你真的要写马的话还是别用了~~。

解密后续流量，主要关注 C2 服务器到客户端的流量，可以得到普通用户的用户名密码（`user:user`，说不定看到 JWT 也能猜出来，就省得分析了）。

登录看看文件共享端点发现 [`hint.py`](./src/seijaku/app/db/models.py) 、[`db.sqlite3`](./challenge/exp.sqlite3) 和 [`.env`](./challenge/exp.env) 文件，根据数据库定义可以发现他 JWT Secret 用的是 AES-GCM 加密。

![image](https://github.com/user-attachments/assets/54cffb3c-be58-4283-b0b3-1f6b10f90507)

读读[源码](https://github.com/kvesteri/sqlalchemy-utils/blob/baf53cd1a3e779fc127010543fed53cf4a97fe16/sqlalchemy_utils/types/encrypted/encrypted_type.py#L171-L196)就可以解密了，拿到解密后的 JWT Secret 伪造 Admin 用户登录，执行 RCE 端点即可拿到 Flag，非常简单。
