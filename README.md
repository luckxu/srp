# SRP简化的反向代理软件（simple reverse proxy）

SRP是基于libevent开发的四层协议的反向代理，使用C语言开发，目前还处于测试阶段。该项目的目的是实现稳定可靠的反向代理工具, 现支持如下特性：

1. 节点与服务端之间为单一TCP长连接(主连接)
2. 数据安全保证，节点与服务器之间的数据都经过AES加密，每个主连接都有独立且随机分配的AES密钥
3. 支持MYSQL数据库，可将大量的节点数据和转发表配置在数据库中
4. 支持流量统计，结果将写入MYSQL数据库
5. 仅支持4层代理转发，不支持任何四层以上的代理

## 使用

服务端和节点端都由一个主程序和一个配置文件组成，采用二进制安装包安装时，主程序存储于/usr/sbin目录，配置文件存储于/etc/srp目录。

1. 服务端由srps程序和srps.conf配置文件组成，运行命令为：`srps [-c config-file] [-l 0-3] [-d]`
2. 节点端由srpn程序和srpn.conf配置文件组成，运行命令为：`srpn [-c config-file] [-l 0-3] [-d]`

参数说明：

* `-c config-file`： 手动指定配置文件，可选项，未指定时从/etc/srp目录读取对应的配置文件
* `-l 0-3`： 指定日志等级，可选值为0至3，其中：0=error, 1=warn， 2=info， 3=debug
* `-d`： 以守护进程方式运行

## 编译和安装

srp支持源码编译、docker镜像、deb和rpm安装包三种方式。

    后续所述make命令都有一个可选的VERSION=xx参数，其中xx是版本号，不指定VERSION参数时使用默认版本号0.0

### 编译

源码可以使用容器编译或GCC编译，编译成功时会在源码目录生成srps和srpn二进制程序：
1. 基于容器编译，目前支持ubuntu 16.04/18.04、centos 7、alpine 3.9容器编译，其它发行版可在scripts/目录下增加相关配置目录，编译完成时会在源码目录生成srps和srpn程序。目前支持的容器编译命令：
   - `make ubuntu-1604-bin` 编译ubuntu 16.04的二进制包
   - `make ubuntu-1804-bin` 编译ubuntu 18.04的二进制包
   - `make centos-7-bin` 编译centos7的二进制包
   - `make alpine-bin` 编译alpine 3.9的二进制包
2. GCC编译，安装相关编译依赖后执行`make release`命令完成编译，相关依赖也可scripts容器相关的dev-image-dockerfile中找到，依赖安装命令：
   - ubuntu 16.04/18.04执行：`apt install -y gcc make libssl-dev libevent-dev libmysqlclient-dev`
   - centos 7执行: `yum install -y gcc make openssl-devel libevent-devel mariadb-devel rpmdevtools`
   - alpine 3.9执行：`apk add gcc make libc-dev openssl-dev linux-headers libevent-dev mariadb-dev mariadb-client`

### 容器构建

1. 构建安装包，支持基于容器的发行版软件包(deb/rpm)构建，目前支持ubuntu 16.04/18.04、centos 7、alpine 3.9软件包构建，命令：
   - `make ubuntu-1604-deb` 构建ubuntu 16.04 deb包
   - `make ubuntu-1804-deb` 构建ubuntu 18.04 deb包
   - `make centos-7-rpm` 构建centos7 rpm包
2. 构建docker容器，支持构建基于alpine:3.9的srp容器，命令：
   - `make alpine-docker` 构建基于alpine的srps容器
3. 构建第1、2所述所有安装包和容器命令：
   - `make pkg-release` 构建上述三个发行版的安装包

### docker镜像

本程序提供了基于alpine 3.9的srps/srpn容器，镜像地址:`lockxu/srp:latest`。因为srp会在主连接建立后监听新的端口，因此使用容器时需要特别注意端口映射。

- 如果只有少量监听端口，运行时增加-p参数手动增加端口绑定
- 如果要监听大量端口，且这些端口都需要暴露给其它应用时，建议运行docker时使用--network host选项，选择主机网络

### DEB/RPM安装包

 [release]([sdafasdf](https://github.com/luckxu/srp/releases)) 页面提供了64位deb和rpm安装包下载，安装前需要安装相关依赖：
 - `yum install -y openssl-libs libevent` centos运行srpn所需依赖
 - `yum install -y openssl-libs libevent mariadb-libs` centos运行srps所需依赖
 - `apt install -y libssl1.0.0 libevent-2.0-5` ubuntu 16.04运行srpn所需依赖
 - `apt install -y libssl1.0.0 libevent-2.0-5 libmysqlclient20` ubuntu 16.04运行srps所需依赖
 - `apt install -y libssl1.1 libevent-2.1-6` ubuntu 18.04运行srpn所需依赖
 - `apt install -y libssl1.1 libevent-2.1-6 libmysqlclient20` ubuntu 18.04运行srps所需依赖

## 原理

### 数据收发过程
SRP由srpn(srp node节点)和srps(srp server服务器)组成，分别部署在节点端和服务端，两者之间通过TCP连接并完成数据收发。srps和srpn之间建立连接需要给过如下几个步骤：
1. 节点与服务端的代理端口（默认为511)建立主连接，服务端从/dev/urandom读取16字节随机数作为主连接的AES128密钥
2. 节点发送随机生成的RSA(2048)公钥
3. 服务端接收到RSA公钥后使用RSA公钥加密AES密钥并发送至节点，后续节点与服务端之间的数据使用AES密钥加密传输
4. 节点上传uuid和password至服务端
5. 服务端收到uuid和password后查找比对uuid和password是否正确以及是否有转发表，比对数据可存储在配置文件或mysql数据库中。
   > - 配置文件(默认为/etc/srp/srps.conf)可以配置默认uuid、password和转发表，适用于代理单一节点的情况，不需要配置数据库即可运行
   > - MYSQL数据库适用于较多节点的情况，数据库存储了每个节点的uuid、password和转发表，客户端发送的uuid和password首先进入数据库比对，正确的情况下从数据库拉取转发表
6. 查找到转发表后在转发表记录的监听地址上监听客户端TCP连接
7. 客户端连接到监听地址后，服务端负责转发连接事件消息至节点并在节点和转发地址之间建立连接
8. 服务端转发客户端和节点(转发地址)的数据

### 转发表

转发表用于实现服务端监听和节点转发，由四个属性组成，分别为监听地址、监听选项、转发地址、转发选项，除监听地址和转发地址外，其它都可选，分别说明如下：

   > - 监听地址：`tcp://ip[:port]`，服务端会在ip地址的port端口监听，port可选，不指定或为0时随机分配端口
   > - 转发地址: `{tcp|udp}://ip:port`，服务端在监听地址上产生新连接时，发送消息给节点并由节点发起到转发地址的连接,可选TCP或UDP协议
   > - 监听选项：暂无
   > - 转发选项：多个选项以逗号分隔。可选值：`connect_delay`延迟连接，监听地址上产生新连接时，直至收到客户端发送的数据时才将新连接消息一同发送至节点。

一个已登录的主连接会在转发表的监听地址上监听客户端连接，并将客户端发送的数据转发至节点，节点再将数据转发至转发地址，相似的，转发地址上产生的数据从相反的方向发送至客户端。

### 连接ID

每个连接都有一个64位的连接ID，由服务端连续递增分配，初始值为0。节点端除了将主连接ID标识为UINT64_MAX外，其它连接ID都由服务端决定。一个典型的过程如下:
1. 客户端连接监听地址并为分配ID值A
2. 服务端将ID值A及转发地址一同发送至节点
3. 节点与转发地址建立连接并将连接的ID值设置为A
4. 客户端和转发地址之间的数据都附加了ID值A，节点和服务端通过ID值A识别转发目的地。

### 管理地址

可选地为srps服务端程序配置`manage_listen`管理地址，服务端会在该地址上监听连接并完成一些特殊功能：
1. **连接关联**：客户端与管理地址建立连接后，首先发送一条`forward node_connect_id host_addr`命令，将当前客户端连接与id值为node_connect_id的主连接建立关联。命令执行成功时，向客户端回复`success\n`消息，客户端后续数据都会通过了node_connect_id对应的主连接转发至host_addr地址。当命令执行失败时，回复`error\n`消息并关闭连接。示例: `forward 1234 tcp://127.0.0.1:22\n`,将当前客户端与ID为1234的主连接建立关联，后续客户端的数据通过主连接对应的节点转发至tcp://127.0.0.1:22地址。
2. **临时监听**：客户端与管理地址建立连接后，首先发送一条`listen node_connect_id listen_addr forward_addr expire\n`命令，指示srps在listen_addr地址上监听连接并与node_connect_id对应的主连接关联。listen_addr表示srps需要监听的地址，不指定端口或端口为0表示端口随机分配；forward_add表示节点转发地址，必须有端口号；expire是监听过期时间，单位秒，0表示不过期，srps会每5秒检查监听是否过期并在过期时停止在listen_addr地址上的监听。命令执行成功时，向客户端回复`success\nid:%lu\nport:%u\n`消息并主动关闭连接，其中id为新的监听连接ID，port是监听端口。客户端连接listen_addr监听地址，srps负责转发客户端和(通过主连接/节点转发至)foward_addr之间的数据。失败时返回`error\n`消息，srps主动关闭客户端连接。示例：`listen 1234 tcp://127.0.0.1:33 tcp://127.0.0.1:22 60`，成功时返回示例`success\n1234\n33\n`。
3. **停止连接**：客户端与管理地址建立连接后，首先发送一条`kill node_connect_id`命令，srps将找到并停止相应节点及子连接。命令执行成功时返回`success\n`消息，执行失败时返回`error\n`消息，不管成功或失败，srps会主动关闭客户端连接。示例: `kill 1234`。


## 版权

代码内容采用 [BSD 3-Clause License](LICENSE)
