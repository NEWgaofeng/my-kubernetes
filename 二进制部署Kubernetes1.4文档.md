
##环境准备
###查看centos版本
```
cat /etc/redhat-release 
CentOS Linux release 7.5.1804 (Core) 
```
###网络静态配置
```
 cat /etc/sysconfig/network-scripts/ifcfg-ens33 
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=static
IPADDR=192.168.191.10
NETMASK=255.255.255.0
GATEWAY=192.168.191.2
DNS1=8.8.8.8
DNS2=114.114.114.114
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=stable-privacy
NAME=ens33
UUID=c8bbd3f8-f1ac-4f11-8f2d-69604f55a80a
DEVICE=ens33
ONBOOT=yes
```
###主机名映射
```
cat /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
192.168.191.10 k8s-01 
192.168.191.11 k8s-02
192.168.191.12 k8s-03
192.168.191.13 k8s-04
```
###修改主机名并且刷新主机名显示
```
hostnamectl set-hostname k8s-01
bash
```
###设置网络环境
```
systemctl stop firewalld
systemctl disable firewalld
iptables -F && iptables -X && iptables -F -t nat && iptables -X -t nat
iptables -P FORWARD ACCEPT
swapoff -a
sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
setenforce 0
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
```
###设置免秘钥
```
wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
yum install -y expect

#分发公钥
ssh-keygen -t rsa -P "" -f /root/.ssh/id_rsa
for i in k8s-01 k8s-02 k8s-03 k8s-04;do
expect -c "
spawn ssh-copy-id -i /root/.ssh/id_rsa.pub root@$i
        expect {
                \"*yes/no*\" {send \"yes\r\"; exp_continue}
                \"*password*\" {send \"123456\r\"; exp_continue}
                \"*Password*\" {send \"123456\r\";}
        } "
done 
```
###更新PATH变量
```
echo 'PATH=/opt/k8s/bin:$PATH' >>/etc/profile
source  /etc/profile
```
###安装依赖包
```
yum install -y conntrack ntpdate ntp ipvsadm ipset jq iptables curl sysstat libseccomp wget
```
###优化内核参数
```
cat > kubernetes.conf <<EOF
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
net.ipv4.tcp_tw_recycle=0
vm.swappiness=0 # 禁止使用 swap 空间，只有当系统 OOM 时才允许使用它
vm.overcommit_memory=1 # 不检查物理内存是否够用
vm.panic_on_oom=0 # 开启 OOM
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
fs.file-max=52706963
fs.nr_open=52706963
net.ipv6.conf.all.disable_ipv6=1
net.netfilter.nf_conntrack_max=2310720
EOF
cp kubernetes.conf  /etc/sysctl.d/kubernetes.conf
sysctl -p /etc/sysctl.d/kubernetes.conf
```
###时区设置
```
 #将当前的 UTC 时间写入硬件时钟
  #重启依赖于系统时间的服务

timedatectl set-timezone Asia/Shanghai
timedatectl set-local-rtc 0
systemctl restart rsyslog 
systemctl restart crond
```
###创建相关目录
```
mkdir -p  /opt/k8s/{bin,work} /etc/{kubernetes,etcd}/cert
#在所有节点上执行，因为flanneld是在所有节点运行的
```
###请根据IP进行修改
###分发环境变量脚本
```
source environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp environment.sh root@${node_ip}:/opt/k8s/bin/
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/* "
done
```

###安装cfssl工具集
```
mkdir -p /opt/k8s/cert && cd /opt/k8s
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
mv cfssl_linux-amd64 /opt/k8s/bin/cfssl
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
mv cfssljson_linux-amd64 /opt/k8s/bin/cfssljson
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
mv cfssl-certinfo_linux-amd64 /opt/k8s/bin/cfssl-certinfo
chmod +x /opt/k8s/bin/*
export PATH=/opt/k8s/bin:$PATH
```

###创建ca配置文件
```
cd /opt/k8s/work
cat > ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "87600h"
      }
    }
  }
}
EOF
```
######################
```
signing 表示该证书可用于签名其它证书，生成的ca.pem证书找中CA=TRUE
server auth 表示client可以用该证书对server提供的证书进行验证
client auth 表示server可以用该证书对client提供的证书进行验证
```
###创建证书签名请求文件
```
cd /opt/k8s/work
cat > ca-csr.json <<EOF
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ],
  "ca": {
    "expiry": "876000h"
 }
}
EOF
```
###生成CA证书和私钥
```
cd /opt/k8s/work
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
ls ca*
```
###分发证书
```
#将生成的CA证书、秘钥文件、配置文件拷贝到所有节点的/etc/kubernetes/cert目录下

cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/kubernetes/cert"
    scp ca*.pem ca-config.json root@${node_ip}:/etc/kubernetes/cert
  done
```
###部署kubectl命令行工具
```
kubectl默认从~/.kube/config读取kube-apiserver地址和认证信息。kube/config只需要部署一次，生成的kubeconfig文件是通用的

下载和解压kubectl

cd /opt/k8s/work
wget http://down.i4t.com/k8s1.14/kubernetes-client-linux-amd64.tar.gz
tar -xzvf kubernetes-client-linux-amd64.tar.gz
分发所有使用kubectl节点

cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kubernetes/client/bin/kubectl root@${node_ip}:/opt/k8s/bin/
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
  ```
  #创建admin证书和私钥
```
kubectl与apiserver https通信，apiserver对提供的证书进行认证和授权。kubectl作为集群的管理工具，需要被授予最高权限，这里创建具有最高权限的admin证书

创建证书签名请求

cd /opt/k8s/work
cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```
###生成证书和私钥
```
cd /opt/k8s/work
cfssl gencert -ca=/opt/k8s/work/ca.pem \
  -ca-key=/opt/k8s/work/ca-key.pem \
  -config=/opt/k8s/work/ca-config.json \
  -profile=kubernetes admin-csr.json | cfssljson -bare admin
ls admin*
```
###kubeconfig为kubectl的配置文件，包含访问apiserver的所有信息，如apiserver地址、CA证书和自身使用的证书
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/work/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kubectl.kubeconfig
kubectl config set-credentials admin \
  --client-certificate=/opt/k8s/work/admin.pem \
  --client-key=/opt/k8s/work/admin-key.pem \
  --embed-certs=true \
  --kubeconfig=kubectl.kubeconfig
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin \
  --kubeconfig=kubectl.kubeconfig
kubectl config use-context kubernetes --kubeconfig=kubectl.kubeconfig

################
--certificate-authority 验证kube-apiserver证书的根证书
--client-certificate、--client-key 刚生成的admin证书和私钥，连接kube-apiserver时使用
--embed-certs=true 将ca.pem和admin.pem证书嵌入到生成的kubectl.kubeconfig文件中 (如果不加入，写入的是证书文件路径，后续拷贝kubeconfig到其它机器时，还需要单独拷贝证书)
```
###分发kubeconfig文件
```
分发到所有使用kubectl命令的节点

cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ~/.kube"
    scp kubectl.kubeconfig root@${node_ip}:~/.kube/config
  done

#保存文件名为~/.kube/config
```

###部署ETCD集群
```
下载和分发etcd二进制文件
创建etcd集群各节点的x509证书，用于加密客户端(如kubectl)与etcd集群、etcd集群之间的数据流
创建etcd的system unit文件，配置服务参数
检查集群工作状态
etcd集群各节点的名称和IP如下
k8s-01 192.168.191.10
k8s-02 192.168.191.11
k8s-03 192.168.191.12
注意: 没有特殊说明都在k8s-01节点操作
```
###下载和分发etcd二进制文件
```
cd /opt/k8s/work
wget http://down.i4t.com/k8s1.14/etcd-v3.3.13-linux-amd64.tar.gz
tar -xvf etcd-v3.3.13-linux-amd64.tar.gz
```
###分发二进制文件到集群节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${ETCD_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp etcd-v3.3.13-linux-amd64/etcd* root@${node_ip}:/opt/k8s/bin
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
```
####创建etcd证书和私钥
```
cd /opt/k8s/work
cat > etcd-csr.json <<EOF
{
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "192.168.191.10",
    "192.168.191.11",
    "192.168.191.12"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```
###生成证书和私钥
```
cd /opt/k8s/work
cfssl gencert -ca=/opt/k8s/work/ca.pem \
    -ca-key=/opt/k8s/work/ca-key.pem \
    -config=/opt/k8s/work/ca-config.json \
    -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
ls etcd*pem
```
####分发证书和私钥到etcd各个节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${ETCD_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/etcd/cert"
    scp etcd*.pem root@${node_ip}:/etc/etcd/cert/
  done
```
###创建etcd的启动文件 (这里将配置文件也存放在启动文件里)
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > etcd.service.template <<EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos
[Service]
Type=notify
WorkingDirectory=${ETCD_DATA_DIR}
ExecStart=/opt/k8s/bin/etcd \\
  --data-dir=${ETCD_DATA_DIR} \\
  --wal-dir=${ETCD_WAL_DIR} \\
  --name=##NODE_NAME## \\
  --cert-file=/etc/etcd/cert/etcd.pem \\
  --key-file=/etc/etcd/cert/etcd-key.pem \\
  --trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-cert-file=/etc/etcd/cert/etcd.pem \\
  --peer-key-file=/etc/etcd/cert/etcd-key.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --listen-peer-urls=https://##NODE_IP##:2380 \\
  --initial-advertise-peer-urls=https://##NODE_IP##:2380 \\
  --listen-client-urls=https://##NODE_IP##:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls=https://##NODE_IP##:2379 \\
  --initial-cluster-token=etcd-cluster-0 \\
  --initial-cluster=${ETCD_NODES} \\
  --initial-cluster-state=new \\
  --auto-compaction-mode=periodic \\
  --auto-compaction-retention=1 \\
  --max-request-bytes=33554432 \\
  --quota-backend-bytes=6442450944 \\
  --heartbeat-interval=250 \\
  --election-timeout=2000
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
```
###为各个节点分发启动文件
```
#分发会将配置文件中的#替换成ip
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for (( i=0; i < 3; i++ ))
  do
    sed -e "s/##NODE_NAME##/${MASTER_NAMES[i]}/" -e "s/##NODE_IP##/${ETCD_IPS[i]}/" etcd.service.template > etcd-${ETCD_IPS[i]}.service 
  done
ls *.service

#NODE_NAMES 和 NODE_IPS 为相同长度的 bash 数组，分别为节点名称和对应的 IP；
```
###分发生成的etcd启动文件到对应的服务器
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp etcd-${node_ip}.service root@${node_ip}:/etc/systemd/system/etcd.service
  done
```
###重命名etcd启动文件并启动etcd服务
```
etcd首次进程启动会等待其他节点加入etcd集群，执行启动命令会卡顿一会，为正常现象

cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${ETCD_DATA_DIR} ${ETCD_WAL_DIR}"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable etcd && systemctl restart etcd " &
  done

#这里我们创建了etcd的工作目录
```
###检查启动结果
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status etcd|grep Active"
  done
```
###如果etcd集群状态不是active (running)，请使用下面命令查看etcd日志
```
journalctl -fu etcd
```

###验证ETCD集群状态
```
验证完etcd集群后，在任一etcd节点执行下命令

cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ETCDCTL_API=3 /opt/k8s/bin/etcdctl \
    --endpoints=https://${node_ip}:2379 \
    --cacert=/etc/kubernetes/cert/ca.pem \
    --cert=/etc/etcd/cert/etcd.pem \
    --key=/etc/etcd/cert/etcd-key.pem endpoint health
  done
  ```
###我们还可以通过下面命令查看当前etcd集群leader
```
source /opt/k8s/bin/environment.sh
ETCDCTL_API=3 /opt/k8s/bin/etcdctl \
  -w table --cacert=/etc/kubernetes/cert/ca.pem \
  --cert=/etc/etcd/cert/etcd.pem \
  --key=/etc/etcd/cert/etcd-key.pem \
  --endpoints=${ETCD_ENDPOINTS} endpoint status
```
###部署Flannel网络
```
下载分发flanneld二进制文件 (本次flanneld不使用Pod运行)

cd /opt/k8s/work
mkdir flannel
wget http://down.i4t.com/k8s1.14/flannel-v0.11.0-linux-amd64.tar.gz
tar -xzvf flannel-v0.11.0-linux-amd64.tar.gz -C flannel
```
###分发二进制文件到所有集群的节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp flannel/{flanneld,mk-docker-opts.sh} root@${node_ip}:/opt/k8s/bin/
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
```
###创建Flannel证书和私钥
```
flanneld从etcd集群存取网段分配信息，而etcd集群开启了双向x509证书认证，所以需要为flannel生成证书和私钥

创建证书签名请求

cd /opt/k8s/work
cat > flanneld-csr.json <<EOF
{
  "CN": "flanneld",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```
###生成证书和私钥
```
cfssl gencert -ca=/opt/k8s/work/ca.pem \
  -ca-key=/opt/k8s/work/ca-key.pem \
  -config=/opt/k8s/work/ca-config.json \
  -profile=kubernetes flanneld-csr.json | cfssljson -bare flanneld
ls flanneld*pem
```
###将生成的证书和私钥分发到所有节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/flanneld/cert"
    scp flanneld*.pem root@${node_ip}:/etc/flanneld/cert
  done
```
###向etcd写入Pod网段信息
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/opt/k8s/work/ca.pem \
  --cert-file=/opt/k8s/work/flanneld.pem \
  --key-file=/opt/k8s/work/flanneld-key.pem \
  mk ${FLANNEL_ETCD_PREFIX}/config '{"Network":"'${CLUSTER_CIDR}'", "SubnetLen": 21, "Backend": {"Type": "vxlan"}}'

  注意:

flanneld当前版本v0.11.0不支持etcd v3，故使用etcd v2 API写入配置Key和网段数据；

写入的Pod网段${CLUSTER_CIDR}地址段(如/16)必须小于SubnetLen，必须与kube-controller-manager的–cluster-cidr参数一致
```
###创建flanneld的启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > flanneld.service << EOF
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service
[Service]
Type=notify
ExecStart=/opt/k8s/bin/flanneld \\
  -etcd-cafile=/etc/kubernetes/cert/ca.pem \\
  -etcd-certfile=/etc/flanneld/cert/flanneld.pem \\
  -etcd-keyfile=/etc/flanneld/cert/flanneld-key.pem \\
  -etcd-endpoints=${ETCD_ENDPOINTS} \\
  -etcd-prefix=${FLANNEL_ETCD_PREFIX} \\
  -iface=${IFACE} \\
  -ip-masq
ExecStartPost=/opt/k8s/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=always
RestartSec=5
StartLimitInterval=0
[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF


mk-docker-opts.sh 脚本将分配给 flanneld 的 Pod 子网段信息写入 /run/flannel/docker 文件，后续 docker 启动时使用这个文件中的环境变量配置 docker0 网桥；
flanneld 使用系统缺省路由所在的接口与其它节点通信，对于有多个网络接口（如内网和公网）的节点，可以用 -iface 参数指定通信接口;
flanneld 运行时需要 root 权限；
-ip-masq: flanneld 为访问 Pod 网络外的流量设置 SNAT 规则，同时将传递给 Docker 的变量 –ip-masq（/run/flannel/docker 文件中）设置为 false，这样 Docker 将不再创建 SNAT 规则； Docker 的 –ip-masq 为 true 时，创建的 SNAT 规则比较“暴力”：将所有本节点 Pod 发起的、访问非 docker0 接口的请求做 SNAT，这样访问其他节点 Pod 的请求来源 IP 会被设置为 flannel.1 接口的 IP，导致目的 Pod 看不到真实的来源 Pod IP。 flanneld 创建的 SNAT 规则比较温和，只对访问非 Pod 网段的请求做 SNAT。
```
###分发启动文件到所有节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp flanneld.service root@${node_ip}:/etc/systemd/system/
  done
```
###启动flanneld服务
```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable flanneld && systemctl restart flanneld"
  done
  ```
  ###检查启动结果
```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status flanneld|grep Active"
  done
```
###检查分配给flanneld的Pod网段信息
```
source /opt/k8s/bin/environment.sh
etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/config
```
###查看已分配的Pod子网网段列表
```
source /opt/k8s/bin/environment.sh
etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  ls ${FLANNEL_ETCD_PREFIX}/subnets
```
###查看某Pod网段对应节点IP和flannel接口地址
```
source /opt/k8s/bin/environment.sh
etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/subnets/172.30.144.0-21

#后面节点IP需要根据我们查出来的地址进行修改
#比如我粘贴复制就报错了key not found 了 

/kubernetes/network/subnets/172.30.144.0-21
/kubernetes/network/subnets/172.30.192.0-21
/kubernetes/network/subnets/172.30.208.0-21
/kubernetes/network/subnets/172.30.200.0-21

#这里我填写的是172.30.144.0-21
```

###查看节点flannel网络信息
```
ip addr show
```
###flannel.1网卡的地址为分配的pod自网段的第一个个IP (.0)，且是/32的地址
```
ip addr show|grep flannel.1
```
###其余三个节点进行操作
```
到其它节点 Pod 网段请求都被转发到 flannel.1 网卡；

flanneld 根据 etcd 中子网段的信息，如 ${FLANNEL_ETCD_PREFIX}/subnets/172.30.80.0-21，来决定进请求发送给哪个节点的互联 IP；

验证各节点能通过 Pod 网段互通

在各节点上部署 flannel 后，检查是否创建了 flannel 接口(名称可能为 flannel0、flannel.0、flannel.1 等)：
```
###其余1 2 3个节点 
```
source /opt/k8s/bin/environment.sh
etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/subnets/172.30.192.0-21
  _______________________________________________________
  source /opt/k8s/bin/environment.sh
etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/subnets/172.30.208.0-21
  ________________________________________________________
    source /opt/k8s/bin/environment.sh
etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/subnets/172.30.200.0-21
```
###查看各个节点的ip情况
```
ip addr show
ip addr show|grep flannel.1
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh ${node_ip} "/usr/sbin/ip addr show flannel.1|grep -w inet"
  done
```
###kube-apiserver 高可用
```
使用Nginx 4层透明代理功能实现k8s节点(master节点和worker节点)高可用访问kube-apiserver的步骤
控制节点的kube-controller-manager、kube-scheduler是多实例部署，所以只要一个实例正常，就可以保证集群高可用
集群内的Pod使用k8s服务域名kubernetes访问kube-apiserver，kube-dns会自动解析多个kube-apiserver节点的IP，所以也是高可用的
在每个Nginx进程，后端对接多个apiserver实例，Nginx对他们做健康检查和负载均衡
kubelet、kube-proxy、controller-manager、schedule通过本地nginx (监听我们vip 192.158.0.54)访问kube-apiserver，从而实现kube-apiserver高可用
```
###下载编译nginx (k8s-01安装就可以，后面有拷贝步骤)
```
cd /opt/k8s/work
wget http://down.i4t.com/k8s1.14/nginx-1.15.3.tar.gz
tar -xzvf nginx-1.15.3.tar.gz

#编译
cd /opt/k8s/work/nginx-1.15.3
mkdir nginx-prefix
./configure --with-stream --without-http --prefix=$(pwd)/nginx-prefix --without-http_uwsgi_module 
make && make install

#############
--without-http_scgi_module --without-http_fastcgi_module
--with-stream：开启 4 层透明转发(TCP Proxy)功能；
--without-xxx：关闭所有其他功能，这样生成的动态链接二进制程序依赖最小；
```
###查看 nginx 动态链接的库：
```
ldd ./nginx-prefix/sbin/nginx
```
###创建目录结构
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    mkdir -p /opt/k8s/kube-nginx/{conf,logs,sbin}
  done
```
###拷贝二进制程序到其他主机 (有报错执行2遍就可以)
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp /opt/k8s/work/nginx-1.15.3/nginx-prefix/sbin/nginx  root@${node_ip}:/opt/k8s/kube-nginx/sbin/kube-nginx
    ssh root@${node_ip} "chmod a+x /opt/k8s/kube-nginx/sbin/*"
    ssh root@${node_ip} "mkdir -p /opt/k8s/kube-nginx/{conf,logs,sbin}"
    sleep 3
  done
```
###配置Nginx文件，开启4层透明转发
```
cd /opt/k8s/work
cat > kube-nginx.conf <<EOF
worker_processes 1;
events {
    worker_connections  1024;
}
stream {
    upstream backend {
        hash $remote_addr consistent;
        server 192.168.191.10:6443        max_fails=3 fail_timeout=30s;
        server 192.168.191.11:6443        max_fails=3 fail_timeout=30s;
        server 192.168.191.12:6443        max_fails=3 fail_timeout=30s;
    }
    server {
        listen *:8443;
        proxy_connect_timeout 1s;
        proxy_pass backend;
    }
}
EOF

#这里需要将server替换我们自己的地址
```
###分发配置文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-nginx.conf  root@${node_ip}:/opt/k8s/kube-nginx/conf/kube-nginx.conf
  done
```
###配置Nginx启动文件
```
cd /opt/k8s/work
cat > kube-nginx.service <<EOF
[Unit]
Description=kube-apiserver nginx proxy
After=network.target
After=network-online.target
Wants=network-online.target
[Service]
Type=forking
ExecStartPre=/opt/k8s/kube-nginx/sbin/kube-nginx -c /opt/k8s/kube-nginx/conf/kube-nginx.conf -p /opt/k8s/kube-nginx -t
ExecStart=/opt/k8s/kube-nginx/sbin/kube-nginx -c /opt/k8s/kube-nginx/conf/kube-nginx.conf -p /opt/k8s/kube-nginx
ExecReload=/opt/k8s/kube-nginx/sbin/kube-nginx -c /opt/k8s/kube-nginx/conf/kube-nginx.conf -p /opt/k8s/kube-nginx -s reload
PrivateTmp=true
Restart=always
RestartSec=5
StartLimitInterval=0
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
```
###分发nginx启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-nginx.service  root@${node_ip}:/etc/systemd/system/
  done
```
###启动 kube-nginx 服务
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-nginx && systemctl start kube-nginx"
  done
```
###检查 kube-nginx 服务运行状态
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status kube-nginx |grep 'Active:'"
  done
```

###KeepLived 部署

前面我们也说了，高可用方案需要一个VIP，供集群内部访问
在所有master节点安装keeplived
```
yum  install -y keepalived
```
###接下来我们要配置keeplive服务

192.168.0.50配置

cat > /etc/keepalived/keepalived.conf <<EOF
! Configuration File for keepalived
global_defs {
   router_id 192.168.191.10
}
vrrp_script chk_nginx {
    script "/etc/keepalived/check_port.sh 8443"
    interval 2
    weight -20
}
vrrp_instance VI_1 {
    state MASTER
    interface ens33
    virtual_router_id 251
    priority 100
    advert_int 1
    mcast_src_ip 192.168.191.10
    nopreempt
    authentication {
        auth_type PASS
        auth_pass 11111111
    }
    track_script {
         chk_nginx
    }
    virtual_ipaddress {
        192.168.191.13
    }
}
EOF

## 192.168.0.50 为节点IP，192.168.0.54位VIP
###将配置拷贝到其他节点，并替换相关IP
```
for node_ip in 192.168.191.10 192.168.191.11 192.168.191.12
  do
    echo ">>> ${node_ip}"
    scp  /etc/keepalived/keepalived.conf $node_ip:/etc/keepalived/keepalived.conf
  done

#替换IP
ssh root@192.168.191.10  sed -i 's#192.168.191.10#192.168.191.11#g'  /etc/keepalived/keepalived.conf
ssh root@192.168.191.12  sed -i 's#192.168.191.10#192.168.191.12#g'  /etc/keepalived/keepalived.conf

#192.168.0.50不替换是因为已经修改好了
```
###创建健康检查脚本  (做到了这里)
```
vim  /opt/check_port.sh 
CHK_PORT=$1
 if [ -n "$CHK_PORT" ];then
        PORT_PROCESS=`ss -lt|grep $CHK_PORT|wc -l`
        if [ $PORT_PROCESS -eq 0 ];then
                echo "Port $CHK_PORT Is Not Used,End."
                exit 1
        fi
 else
        echo "Check Port Cant Be Empty!"1
 fi
```
###启动keeplived
```
for NODE in k8s-01 k8s-02 k8s-03; do
    echo "--- $NODE ---"
    scp -r /opt/check_port.sh  $NODE:/etc/keepalived/
    ssh $NODE 'systemctl enable --now keepalived.service'
done
```
###启动完毕后ping 192.168.0.54 (VIP)
```
因为要快速搭建完毕 不能浪费太多时间 所以这里的keepalived高可用暂时是没成功的
找时间改下配置文件即可,一些参数稍微一改改就可以启动成功 主要是做到现在还没有
用到整个Keepalived集群的作用 暂时搁置 .
```
###部署master节点
```
kubernetes master节点运行组件如下:kube-apiserver、kube-scheduler、kube-controller-manager、kube-nginx

kube-apiserver、kube-scheduler、kube-controller-manager均以多实例模式运行
kube-scheduler和kube-controller-manager会自动选举一个leader实例，其他实例处于阻塞模式，当leader挂了后，重新选举产生的leader，从而保证服务可用性
kube-apiserver是无状态的，需要通过kube-nginx进行代理访问，从而保证服务可用性
```
###以下操作都在K8s-01操作
```
下载kubernetes二进制包，并分发到所有master节点

cd /opt/k8s/work
wget http://down.i4t.com/k8s1.14/kubernetes-server-linux-amd64.tar.gz
tar -xzvf kubernetes-server-linux-amd64.tar.gz
cd kubernetes
tar -xzvf  kubernetes-src.tar.gz
```
###将压缩包的文件拷贝到所有master节点上
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kubernetes/server/bin/kube-apiserver root@${node_ip}:/opt/k8s/bin/
    scp kubernetes/server/bin/{apiextensions-apiserver,cloud-controller-manager,kube-controller-manager,kube-proxy,kube-scheduler,kubeadm,kubectl,kubelet,mounter} root@${node_ip}:/opt/k8s/bin/
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done

#同时将kubelet kube-proxy拷贝到所有节点

cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kubernetes/server/bin/{kubelet,kube-proxy} root@${node_ip}:/opt/k8s/bin/
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
```
###创建Kubernetes 证书和私钥
```
创建签证签名请求
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > kubernetes-csr.json <<EOF
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "192.168.191.10",
    "192.168.191.11",
    "192.168.191.12",
    "192.168.191.13",
    "10.254.0.1",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local."
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF

#需要将集群的所有IP及VIP添加进去
#如果要添加注意最后的逗号，不要忘记添加，否则下一步报错

```
###hosts 字段指定授权使用该证书的IP和域名列表，这里列出了master节点IP、kubernetes服务的IP和域名
```
kubernetes serviceIP是apiserver自动创建的，一般是–service-cluster-ip-range参数指定的网段的第一个IP

$ kubectl get svc kubernetes
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.254.0.1           443/TCP   31d

#目前我们是看不到
```
###生成证书和私钥
```
    cfssl gencert -ca=/opt/k8s/work/ca.pem \
      -ca-key=/opt/k8s/work/ca-key.pem \
      -config=/opt/k8s/work/ca-config.json \
      -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes
    ls kubernetes*pem
```
###将生成的证书和私钥文件拷贝到所有master节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/kubernetes/cert"
    scp kubernetes*.pem root@${node_ip}:/etc/kubernetes/cert/
  done
```
###创建加密配置文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > encryption-config.yaml <<EOF
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: ${ENCRYPTION_KEY}
      - identity: {}
EOF
```
###将加密配置文件拷贝到master节点的/etc/kubernetes目录下
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp encryption-config.yaml root@${node_ip}:/etc/kubernetes/
  done
```
###创建审计策略文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > audit-policy.yaml <<EOF
apiVersion: audit.k8s.io/v1beta1
kind: Policy
rules:
  # The following requests were manually identified as high-volume and low-risk, so drop them.
  - level: None
    resources:
      - group: ""
        resources:
          - endpoints
          - services
          - services/status
    users:
      - 'system:kube-proxy'
    verbs:
      - watch
  - level: None
    resources:
      - group: ""
        resources:
          - nodes
          - nodes/status
    userGroups:
      - 'system:nodes'
    verbs:
      - get
  - level: None
    namespaces:
      - kube-system
    resources:
      - group: ""
        resources:
          - endpoints
    users:
      - 'system:kube-controller-manager'
      - 'system:kube-scheduler'
      - 'system:serviceaccount:kube-system:endpoint-controller'
    verbs:
      - get
      - update
  - level: None
    resources:
      - group: ""
        resources:
          - namespaces
          - namespaces/status
          - namespaces/finalize
    users:
      - 'system:apiserver'
    verbs:
      - get
  # Don't log HPA fetching metrics.
  - level: None
    resources:
      - group: metrics.k8s.io
    users:
      - 'system:kube-controller-manager'
    verbs:
      - get
      - list
  # Don't log these read-only URLs.
  - level: None
    nonResourceURLs:
      - '/healthz*'
      - /version
      - '/swagger*'
  # Don't log events requests.
  - level: None
    resources:
      - group: ""
        resources:
          - events
  # node and pod status calls from nodes are high-volume and can be large, don't log responses for expected updates from nodes
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - nodes/status
          - pods/status
    users:
      - kubelet
      - 'system:node-problem-detector'
      - 'system:serviceaccount:kube-system:node-problem-detector'
    verbs:
      - update
      - patch
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - nodes/status
          - pods/status
    userGroups:
      - 'system:nodes'
    verbs:
      - update
      - patch
  # deletecollection calls can be large, don't log responses for expected namespace deletions
  - level: Request
    omitStages:
      - RequestReceived
    users:
      - 'system:serviceaccount:kube-system:namespace-controller'
    verbs:
      - deletecollection
  # Secrets, ConfigMaps, and TokenReviews can contain sensitive & binary data,
  # so only log at the Metadata level.
  - level: Metadata
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - secrets
          - configmaps
      - group: authentication.k8s.io
        resources:
          - tokenreviews
  # Get repsonses can be large; skip them.
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
      - group: admissionregistration.k8s.io
      - group: apiextensions.k8s.io
      - group: apiregistration.k8s.io
      - group: apps
      - group: authentication.k8s.io
      - group: authorization.k8s.io
      - group: autoscaling
      - group: batch
      - group: certificates.k8s.io
      - group: extensions
      - group: metrics.k8s.io
      - group: networking.k8s.io
      - group: policy
      - group: rbac.authorization.k8s.io
      - group: scheduling.k8s.io
      - group: settings.k8s.io
      - group: storage.k8s.io
    verbs:
      - get
      - list
      - watch
  # Default level for known APIs
  - level: RequestResponse
    omitStages:
      - RequestReceived
    resources:
      - group: ""
      - group: admissionregistration.k8s.io
      - group: apiextensions.k8s.io
      - group: apiregistration.k8s.io
      - group: apps
      - group: authentication.k8s.io
      - group: authorization.k8s.io
      - group: autoscaling
      - group: batch
      - group: certificates.k8s.io
      - group: extensions
      - group: metrics.k8s.io
      - group: networking.k8s.io
      - group: policy
      - group: rbac.authorization.k8s.io
      - group: scheduling.k8s.io
      - group: settings.k8s.io
      - group: storage.k8s.io
  # Default level for all other requests.
  - level: Metadata
    omitStages:
      - RequestReceived
EOF
```
###分发审计策略文件：
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp audit-policy.yaml root@${node_ip}:/etc/kubernetes/audit-policy.yaml
  done
```
###创建证书签名请求
```
cat > proxy-client-csr.json <<EOF
{
  "CN": "aggregator",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
CN名称需要位于kube-apiserver的–requestherader-allowed-names参数中，否则后续访问metrics时会提示权限不足
```
###生成证书和私钥
```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem  \
  -config=/etc/kubernetes/cert/ca-config.json  \
  -profile=kubernetes proxy-client-csr.json | cfssljson -bare proxy-client
ls proxy-client*.pem
```
###将生成的证书和私钥文件拷贝到master节点
```
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp proxy-client*.pem root@${node_ip}:/etc/kubernetes/cert/
  done
```
###创建kube-apiserver启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > kube-apiserver.service.template <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
[Service]
WorkingDirectory=${K8S_DIR}/kube-apiserver
ExecStart=/opt/k8s/bin/kube-apiserver \\
  --advertise-address=##NODE_IP## \\
  --default-not-ready-toleration-seconds=360 \\
  --default-unreachable-toleration-seconds=360 \\
  --feature-gates=DynamicAuditing=true \\
  --max-mutating-requests-inflight=2000 \\
  --max-requests-inflight=4000 \\
  --default-watch-cache-size=200 \\
  --delete-collection-workers=2 \\
  --encryption-provider-config=/etc/kubernetes/encryption-config.yaml \\
  --etcd-cafile=/etc/kubernetes/cert/ca.pem \\
  --etcd-certfile=/etc/kubernetes/cert/kubernetes.pem \\
  --etcd-keyfile=/etc/kubernetes/cert/kubernetes-key.pem \\
  --etcd-servers=${ETCD_ENDPOINTS} \\
  --bind-address=##NODE_IP## \\
  --secure-port=6443 \\
  --tls-cert-file=/etc/kubernetes/cert/kubernetes.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kubernetes-key.pem \\
  --insecure-port=0 \\
  --audit-dynamic-configuration \\
  --audit-log-maxage=15 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-truncate-enabled \\
  --audit-log-path=${K8S_DIR}/kube-apiserver/audit.log \\
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \\
  --profiling \\
  --anonymous-auth=false \\
  --client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --enable-bootstrap-token-auth \\
  --requestheader-allowed-names="aggregator" \\
  --requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-extra-headers-prefix="X-Remote-Extra-" \\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User \\
  --service-account-key-file=/etc/kubernetes/cert/ca.pem \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=api/all=true \\
  --enable-admission-plugins=NodeRestriction \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --event-ttl=168h \\
  --kubelet-certificate-authority=/etc/kubernetes/cert/ca.pem \\
  --kubelet-client-certificate=/etc/kubernetes/cert/kubernetes.pem \\
  --kubelet-client-key=/etc/kubernetes/cert/kubernetes-key.pem \\
  --kubelet-https=true \\
  --kubelet-timeout=10s \\
  --proxy-client-cert-file=/etc/kubernetes/cert/proxy-client.pem \\
  --proxy-client-key-file=/etc/kubernetes/cert/proxy-client-key.pem \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --service-node-port-range=${NODE_PORT_RANGE} \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=10
Type=notify
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
```
###为各个节点创建和分发kube-apiserver启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for (( i=0; i < 3; i++ ))  #这里是三个节点所以为3,请根据实际情况修改,后边不在提示,同理
  do
    sed -e "s/##NODE_NAME##/${MASTER_NAMES[i]}/" -e "s/##NODE_IP##/${MASTER_IPS[i]}/" kube-apiserver.service.template > kube-apiserver-${MASTER_IPS[i]}.service 
  done
ls kube-apiserver*.service
```
###分发apiserver启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-apiserver-${node_ip}.service root@${node_ip}:/etc/systemd/system/kube-apiserver.service
  done
```
###启动apiserver
```
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kube-apiserver"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-apiserver && systemctl restart kube-apiserver"
  done
```
###检查服务是否正常
```
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status kube-apiserver |grep 'Active:'"
  done
```
###确保状态为active (running)，否则查看日志，确认原因
```
 journalctl -u kube-apiserver
```
###打印kube-apiserver写入etcd数据
```
source /opt/k8s/bin/environment.sh
ETCDCTL_API=3 etcdctl \
    --endpoints=${ETCD_ENDPOINTS} \
    --cacert=/opt/k8s/work/ca.pem \
    --cert=/opt/k8s/work/etcd.pem \
    --key=/opt/k8s/work/etcd-key.pem \
    get /registry/ --prefix --keys-only
```
###检查kube-apiserver监听的端口
```
yum install -y net-tools
netstat -lntup|grep kube
```
###检查集群信息
```
kubectl cluster-info
Kubernetes master is running at https://192.168.191.13:8443

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
[root@k8s-01 work]# kubectl get all --all-namespaces
NAMESPACE   NAME                 TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
default     service/kubernetes   ClusterIP   10.254.0.1   <none>        443/TCP   4m39s
[root@k8s-01 work]# kubectl get componentstatuses
NAME                 STATUS      MESSAGE                                                                                     ERROR
controller-manager   Unhealthy   Get http://127.0.0.1:10252/healthz: dial tcp 127.0.0.1:10252: connect: connection refused   
scheduler            Unhealthy   Get http://127.0.0.1:10251/healthz: dial tcp 127.0.0.1:10251: connect: connection refused   
etcd-1               Healthy     {"health":"true"}                                                                           
etcd-0               Healthy     {"health":"true"}                                                                           
etcd-2               Healthy     {"health":"true"}   
```
###如果提示有报错，请检查~/.kube/config以及配置证书是否有问题
```
在执行kubectl命令时，apiserver会将请求转发到kubelet的https端口。这里定义的RBAC规则，授权apiserver使用的证书(kubernetes.pem)用户名(CN:kubernetes)访问kubelet API的权限
kubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user  kubernetes
```
###部署高可用kube-controller-manager集群
```
该集群包含三个节点，启动后通过竞争选举机制产生一个leader节点，其他节点为阻塞状态。当leader节点不可用时，阻塞节点将会在此选举产生新的leader，从而保证服务的高可用。为保证通信安全，这里采用x509证书和私钥，kube-controller-manager在与apiserver的安全端口（http 10252）通信使用；

创建kube-controller-manager证书和私钥
```
###创建证书签名请求
```
cd /opt/k8s/work
cat > kube-controller-manager-csr.json <<EOF
{
    "CN": "system:kube-controller-manager",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "hosts": [
      "127.0.0.1",
      "192.168.191.10",
      "192.168.191.11",
      "192.168.191.12"
    ],
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-controller-manager",
        "OU": "4Paradigm"
      }
    ]
}
EOF


#这里的IP地址为master ip
```
```
host列表包含所有的kube-controller-manager节点IP(VIP不需要输入)
CN和O均为system:kube-controller-manager，kubernetes内置的ClusterRoleBindings system:kube-controller-manager赋予kube-controller-manager工作所需权限
```
###生成证书和私钥
```
cd /opt/k8s/work
cfssl gencert -ca=/opt/k8s/work/ca.pem \
  -ca-key=/opt/k8s/work/ca-key.pem \
  -config=/opt/k8s/work/ca-config.json \
  -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
ls kube-controller-manager*pem
```

###将生成的证书和私钥分发到所有master节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-controller-manager*.pem root@${node_ip}:/etc/kubernetes/cert/
  done
```
###创建和分发kubeconfig文件

#kube-controller-manager使用kubeconfig文件访问apiserver
#该文件提供了apiserver地址、嵌入的CA证书和kube-controller-manager证书
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/work/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-controller-manager.kubeconfig
kubectl config set-credentials system:kube-controller-manager \
  --client-certificate=kube-controller-manager.pem \
  --client-key=kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-controller-manager.kubeconfig
kubectl config set-context system:kube-controller-manager \
  --cluster=kubernetes \
  --user=system:kube-controller-manager \
  --kubeconfig=kube-controller-manager.kubeconfig
kubectl config use-context system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig
```
###分发kubeconfig到所有master节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-controller-manager.kubeconfig root@${node_ip}:/etc/kubernetes/
  done
```
###创建kube-controller-manager启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > kube-controller-manager.service.template <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
[Service]
WorkingDirectory=${K8S_DIR}/kube-controller-manager
ExecStart=/opt/k8s/bin/kube-controller-manager \\
  --profiling \\
  --cluster-name=kubernetes \\
  --controllers=*,bootstrapsigner,tokencleaner \\
  --kube-api-qps=1000 \\
  --kube-api-burst=2000 \\
  --leader-elect \\
  --use-service-account-credentials\\
  --concurrent-service-syncs=2 \\
  --bind-address=0.0.0.0 \\
  #--secure-port=10252 \\
  --tls-cert-file=/etc/kubernetes/cert/kube-controller-manager.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kube-controller-manager-key.pem \\
  #--port=0 \\
  --authentication-kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-allowed-names="" \\
  --requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-extra-headers-prefix="X-Remote-Extra-" \\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User \\
  --authorization-kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --cluster-signing-cert-file=/etc/kubernetes/cert/ca.pem \\
  --cluster-signing-key-file=/etc/kubernetes/cert/ca-key.pem \\
  --experimental-cluster-signing-duration=876000h \\
  --horizontal-pod-autoscaler-sync-period=10s \\
  --concurrent-deployment-syncs=10 \\
  --concurrent-gc-syncs=30 \\
  --node-cidr-mask-size=24 \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --pod-eviction-timeout=6m \\
  --terminated-pod-gc-threshold=10000 \\
  --root-ca-file=/etc/kubernetes/cert/ca.pem \\
  --service-account-private-key-file=/etc/kubernetes/cert/ca-key.pem \\
  --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
```
###替换启动文件，并分发脚本
```
 cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for (( i=0; i < 3; i++ ))
  do
    sed -e "s/##NODE_NAME##/${MASTER_NAMES[i]}/" -e "s/##NODE_IP##/${MASTER_IPS[i]}/" kube-controller-manager.service.template > kube-controller-manager-${MASTER_IPS[i]}.service 
  done
ls kube-controller-manager*.service
```
###分发到所有master节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-controller-manager-${node_ip}.service root@${node_ip}:/etc/systemd/system/kube-controller-manager.service
  done
```
###启动服务
```
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kube-controller-manager"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-controller-manager && systemctl restart kube-controller-manager"
  done
```
###检查运行状态
```
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status kube-controller-manager|grep Active"
  done
  ```
###检查服务状态
```
netstat -lnpt | grep kube-cont
```
###kube-controller-manager 创建权限
```
ClusteRole system:kube-controller-manager的权限太小，只能创建secret、serviceaccount等资源,将controller的权限分散到ClusterRole system:controller:xxx中
```
```
kubectl describe clusterrole system:kube-controller-manager
Name:         system:kube-controller-manager
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
PolicyRule:
  Resources                                  Non-Resource URLs  Resource Names  Verbs
  ---------                                  -----------------  --------------  -----
  secrets                                    []                 []              [create delete get update]
  endpoints                                  []                 []              [create get update]
  serviceaccounts                            []                 []              [create get update]
  events                                     []                 []              [create patch update]
  tokenreviews.authentication.k8s.io         []                 []              [create]
  subjectaccessreviews.authorization.k8s.io  []                 []              [create]
  configmaps                                 []                 []              [get]
  namespaces                                 []                 []              [get]
  *.*                                        []                 []              [list watch]
```
```
需要在 kube-controller-manager 的启动参数中添加 –use-service-account-credentials=true 参数，这样 main controller 会为各 controller 创建对应的 ServiceAccount XXX-controller。内置的 ClusterRoleBinding system:controller:XXX 将赋予各 XXX-controller ServiceAccount 对应的 ClusterRole system:controller:XXX 权限。
```
```
 kubectl get clusterrole|grep controller
system:controller:attachdetach-controller                              179m
system:controller:certificate-controller                               179m
system:controller:clusterrole-aggregation-controller                   179m
system:controller:cronjob-controller                                   179m
system:controller:daemon-set-controller                                179m
system:controller:deployment-controller                                179m
system:controller:disruption-controller                                179m
system:controller:endpoint-controller                                  179m
system:controller:expand-controller                                    179m
system:controller:generic-garbage-collector                            179m
system:controller:horizontal-pod-autoscaler                            179m
system:controller:job-controller                                       179m
system:controller:namespace-controller                                 179m
system:controller:node-controller                                      179m
system:controller:persistent-volume-binder                             179m
system:controller:pod-garbage-collector                                179m
system:controller:pv-protection-controller                             179m
system:controller:pvc-protection-controller                            179m
system:controller:replicaset-controller                                179m
system:controller:replication-controller                               179m
system:controller:resourcequota-controller                             179m
system:controller:route-controller                                     179m
system:controller:service-account-controller                           179m
system:controller:service-controller                                   179m
system:controller:statefulset-controller                               179m
system:controller:ttl-controller                                       179m
system:kube-controller-manager                                         179m
```
###以 deployment controller 为例：
```
kubectl describe clusterrole system:controller:deployment-controller
Name:         system:controller:deployment-controller
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
PolicyRule:
  Resources                          Non-Resource URLs  Resource Names  Verbs
  ---------                          -----------------  --------------  -----
  replicasets.apps                   []                 []              [create delete get list patch update watch]
  replicasets.extensions             []                 []              [create delete get list patch update watch]
  events                             []                 []              [create patch update]
  pods                               []                 []              [get list update watch]
  deployments.apps                   []                 []              [get list update watch]
  deployments.extensions             []                 []              [get list update watch]
  deployments.apps/finalizers        []                 []              [update]
  deployments.apps/status            []                 []              [update]
  deployments.extensions/finalizers  []                 []              [update]
  deployments.extensions/status      []                 []              [update]
```
###查看当前的 leader
```
kubectl get endpoints kube-controller-manager --namespace=kube-system  -o yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"k8s-01_c7e8ce75-5df6-11ea-b908-000c299ed09c","leaseDurationSeconds":15,"acquireTime":"2020-03-04T09:01:48Z","renewTime":"2020-03-04T09:10:31Z","leaderTransitions":0}'
  creationTimestamp: "2020-03-04T09:01:48Z"
  name: kube-controller-manager
  namespace: kube-system
  resourceVersion: "3822"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-controller-manager
  uid: c7f3d30e-5df6-11ea-9740-000c299ed09c
```

###部署高可用kube-scheduler
```
创建 kube-scheduler 证书和私钥

创建证书签名请求：

cd /opt/k8s/work
cat > kube-scheduler-csr.json <<EOF
{
    "CN": "system:kube-scheduler",
    "hosts": [
      "127.0.0.1",
      "192.168.0.50",
      "192.168.0.51",
      "192.168.0.52"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-scheduler",
        "OU": "4Paradigm"
      }
    ]
}
EOF
```
###生成证书和私钥：
```
cd /opt/k8s/work
cfssl gencert -ca=/opt/k8s/work/ca.pem \
  -ca-key=/opt/k8s/work/ca-key.pem \
  -config=/opt/k8s/work/ca-config.json \
  -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler
ls kube-scheduler*pem
```
###将生成的证书和私钥分发到所有 master 节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler*.pem root@${node_ip}:/etc/kubernetes/cert/
  done
```
###创建和分发 kubeconfig 文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/work/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-scheduler.kubeconfig
kubectl config set-credentials system:kube-scheduler \
  --client-certificate=kube-scheduler.pem \
  --client-key=kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-scheduler.kubeconfig
kubectl config set-context system:kube-scheduler \
  --cluster=kubernetes \
  --user=system:kube-scheduler \
  --kubeconfig=kube-scheduler.kubeconfig
kubectl config use-context system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig
```
###分发 kubeconfig 到所有 master 节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler.kubeconfig root@${node_ip}:/etc/kubernetes/
  done
```
###创建 kube-scheduler 配置文件
```
cd /opt/k8s/work
cat >kube-scheduler.yaml.template <<EOF
apiVersion: kubescheduler.config.k8s.io/v1alpha1
kind: KubeSchedulerConfiguration
bindTimeoutSeconds: 600
clientConnection:
  burst: 200
  kubeconfig: "/etc/kubernetes/kube-scheduler.kubeconfig"
  qps: 100
enableContentionProfiling: false
enableProfiling: true
hardPodAffinitySymmetricWeight: 1
healthzBindAddress: 127.0.0.1:10251
leaderElection:
  leaderElect: true
metricsBindAddress: ##NODE_IP##:10251
EOF
```
###替换模板文件中的变量：
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for (( i=0; i < 3; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" kube-scheduler.yaml.template > kube-scheduler-${NODE_IPS[i]}.yaml
  done
ls kube-scheduler*.yaml
```
###分发 kube-scheduler 配置文件到所有 master 节点：
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler-${node_ip}.yaml root@${node_ip}:/etc/kubernetes/kube-scheduler.yaml
  done
```
###创建kube-scheduler启动文件
```
cd /opt/k8s/work
cat > kube-scheduler.service.template <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
[Service]
WorkingDirectory=${K8S_DIR}/kube-scheduler
ExecStart=/opt/k8s/bin/kube-scheduler \\
  --config=/etc/kubernetes/kube-scheduler.yaml \\
  --bind-address=##NODE_IP## \\
  --secure-port=10259 \\
  --port=0 \\
  --tls-cert-file=/etc/kubernetes/cert/kube-scheduler.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kube-scheduler-key.pem \\
  --authentication-kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
  --client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-allowed-names="" \\
  --requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-extra-headers-prefix="X-Remote-Extra-" \\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User \\
  --authorization-kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
  --logtostderr=true \\
  --v=2
Restart=always
RestartSec=5
StartLimitInterval=0
[Install]
WantedBy=multi-user.target
EOF
```
###分发配置文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for (( i=0; i < 3; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" kube-scheduler.service.template > kube-scheduler-${NODE_IPS[i]}.service 
  done
ls kube-scheduler*.service


cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler-${node_ip}.service root@${node_ip}:/etc/systemd/system/kube-scheduler.service
  done
```
###启动kube-scheduler
```
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kube-scheduler"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-scheduler && systemctl restart kube-scheduler"
done
```
###检查服务运行状态
```
source /opt/k8s/bin/environment.sh
for node_ip in ${MASTER_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status kube-scheduler|grep Active"
  done
```
```
查看输出的 metrics
注意：以下命令在 kube-scheduler 节点上执行。
kube-scheduler 监听 10251 和 10251 端口：
10251：接收 http 请求，非安全端口，不需要认证授权；
10259：接收 https 请求，安全端口，需要认证授权；
两个接口都对外提供 /metrics 和 /healthz 的访问。
```
###查看输出的 metrics
```
curl -s http://192.168.191.10:10251/metrics|head
# HELP apiserver_audit_event_total Counter of audit events generated and sent to the audit backend.
# TYPE apiserver_audit_event_total counter
apiserver_audit_event_total 0
# HELP apiserver_audit_requests_rejected_total Counter of apiserver requests rejected due to an error in audit logging backend.
# TYPE apiserver_audit_requests_rejected_total counter
apiserver_audit_requests_rejected_total 0
# HELP apiserver_client_certificate_expiration_seconds Distribution of the remaining lifetime on the certificate used to authenticate a request.
# TYPE apiserver_client_certificate_expiration_seconds histogram
apiserver_client_certificate_expiration_seconds_bucket{le="0"} 0
apiserver_client_certificate_expiration_seconds_bucket{le="1800"} 0
```
###查看当前leader
```
kubectl get endpoints kube-scheduler --namespace=kube-system  -o yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"k8s-02_eb8587c1-5df8-11ea-993f-000c29be2e5a","leaseDurationSeconds":15,"acquireTime":"2020-03-04T09:21:12Z","renewTime":"2020-03-04T09:28:29Z","leaderTransitions":1}'
  creationTimestamp: "2020-03-04T09:17:07Z"
  name: kube-scheduler
  namespace: kube-system
  resourceVersion: "4973"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-scheduler
  uid: ebb878a8-5df8-11ea-9740-000c299ed09c
```
###work节点安装
```
kubernetes work节点运行如下组件: >docker、kubelet、kube-proxy、flanneld、kube-nginx
前面已经安装flanneld这就不在安装了
安装依赖包
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "yum install -y epel-release"
    ssh root@${node_ip} "yum install -y conntrack ipvsadm ntp ntpdate ipset jq iptables curl sysstat libseccomp && modprobe ip_vs "
  done
```
###部署Docker组件
```
我们在所有节点安装docker，这里使用阿里云的yum安装
Docker步骤需要在所有节点安装
yum install -y yum-utils device-mapper-persistent-data lvm2
yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
yum makecache fast
yum -y install docker-ce
```
###创建配置文件
```
mkdir -p /etc/docker/
cat > /etc/docker/daemon.json <<EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "registry-mirrors": ["https://hjvrgh7a.mirror.aliyuncs.com"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF
#这里配置当时镜像加速器,可以不进行配置，但是建议配置
要添加我们harbor仓库需要在添加下面一行
  "insecure-registries": ["harbor.i4t.com"],
默认docker hub需要https协议，使用上面配置不需要配置https
```

###修改Docker启动参数
```
这里需要在所有的节点上修改docker配置！！
cat /usr/lib/systemd/system/docker.service
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
BindsTo=containerd.service
After=network-online.target firewalld.service containerd.service
Wants=network-online.target
Requires=docker.socket

[Service]
Type=notify
# the default is not to use systemd for cgroups because the delegate issues still
# exists and systemd currently does not support the cgroup feature set required
# for containers run by docker
ExecStart=/usr/bin/dockerd  $DOCKER_NETWORK_OPTIONS -H fd:// --containerd=/run/containerd/containerd.sock
EnvironmentFile=-/run/flannel/docker
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutSec=0
RestartSec=2
Restart=always

# Note that StartLimit* options were moved from "Service" to "Unit" in systemd 229.
# Both the old, and new location are accepted by systemd 229 and up, so using the old location
# to make them work for either version of systemd.
StartLimitBurst=3

# Note that StartLimitInterval was renamed to StartLimitIntervalSec in systemd 230.
# Both the old, and new name are accepted by systemd 230 and up, so using the old name to make
# this option work for either version of systemd.
StartLimitInterval=60s

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity

# Comment TasksMax if your systemd version does not support it.
# Only systemd 226 and above support this option.
TasksMax=infinity

# set delegate yes so that systemd does not reset the cgroups of docker containers
Delegate=yes

# kill only the docker process, not all processes in the cgroup
KillMode=process

[Install]
WantedBy=multi-user.target
```
###启动 docker 服务
```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable docker && systemctl restart docker"
  done
```
###检查服务运行状态
```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status docker|grep Active"
  done
```
###检查 docker0 网桥
```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "/usr/sbin/ip addr show flannel.1 && /usr/sbin/ip addr show docker0"
  done
```
###查看 docker 的状态信息
```
docker info
#查看docker版本以及存储引擎是否是overlay2
```
###部署kubelet组件

kubelet运行在每个worker节点上，接收kube-apiserver发送的请求，管理Pod容器，执行交互命令

kubelet启动时自动向kube-apiserver注册节点信息，内置的cAdivsor统计和监控节点的资源使用资源情况。为确保安全，部署时关闭了kubelet的非安全http端口，对请求进行认证和授权，拒绝未授权的访问

创建kubelet bootstrap kubeconfig文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_name in ${NODE_NAMES[@]}
  do
    echo ">>> ${node_name}"
    # 创建 token
    export BOOTSTRAP_TOKEN=$(kubeadm token create \
      --description kubelet-bootstrap-token \
      --groups system:bootstrappers:${node_name} \
      --kubeconfig ~/.kube/config)
    # 设置集群参数
    kubectl config set-cluster kubernetes \
      --certificate-authority=/etc/kubernetes/cert/ca.pem \
      --embed-certs=true \
      --server=${KUBE_APISERVER} \
      --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig
    # 设置客户端认证参数
    kubectl config set-credentials kubelet-bootstrap \
      --token=${BOOTSTRAP_TOKEN} \
      --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig
    # 设置上下文参数
    kubectl config set-context default \
      --cluster=kubernetes \
      --user=kubelet-bootstrap \
      --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig
    # 设置默认上下文
    kubectl config use-context default --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig
  done
```
```
###向kubeconfig写入的是token，bootstrap结束后kube-controller-manager为kubelet创建client和server证书
查看kubeadm为各个节点创建的token
 kubeadm token list --kubeconfig ~/.kube/config
TOKEN                     TTL       EXPIRES                     USAGES                   DESCRIPTION               EXTRA GROUPS
arc548.wgpkrn86fhivaq95   23h       2020-03-06T14:43:57+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-04
eg8wj5.233dpqcbtxfqk29g   23h       2020-03-06T14:43:57+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-02
k555eq.inr6by091mq0l2z9   23h       2020-03-06T14:43:56+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-01
zfcoqb.ghrdvb2urbb90xwh   23h       2020-03-06T14:43:57+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-03

```
```
token有效期为1天，超期后将不能被用来bootstrap kubelet，且会被kube-controller-manager的token cleaner清理
kube-apiserver接收kubelet的bootstrap token后，将请求的user设置为system:bootstrap; group设置为system:bootstrappers，后续将为这个group设置ClusterRoleBinding

```
###
```
查看各token关联的Secret
kubectl get secrets  -n kube-system|grep bootstrap-token
bootstrap-token-arc548                           bootstrap.kubernetes.io/token         7      5m30s
bootstrap-token-eg8wj5                           bootstrap.kubernetes.io/token         7      5m30s
bootstrap-token-k555eq                           bootstrap.kubernetes.io/token         7      5m31s
bootstrap-token-zfcoqb                           bootstrap.kubernetes.io/token         7      5m30s
```
###分发 bootstrap kubeconfig 文件到所有 worker 节点
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_name in ${NODE_NAMES[@]}
  do
    echo ">>> ${node_name}"
    scp kubelet-bootstrap-${node_name}.kubeconfig root@${node_name}:/etc/kubernetes/kubelet-bootstrap.kubeconfig
  done
```
###创建和分发kubelet参数配置
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > kubelet-config.yaml.template <<EOF
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: "##NODE_IP##"
staticPodPath: ""
syncFrequency: 1m
fileCheckFrequency: 20s
httpCheckFrequency: 20s
staticPodURL: ""
port: 10250
readOnlyPort: 0
rotateCertificates: true
serverTLSBootstrap: true
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/etc/kubernetes/cert/ca.pem"
authorization:
  mode: Webhook
registryPullQPS: 0
registryBurst: 20
eventRecordQPS: 0
eventBurst: 20
enableDebuggingHandlers: true
enableContentionProfiling: true
healthzPort: 10248
healthzBindAddress: "##NODE_IP##"
clusterDomain: "${CLUSTER_DNS_DOMAIN}"
clusterDNS:
  - "${CLUSTER_DNS_SVC_IP}"
nodeStatusUpdateFrequency: 10s
nodeStatusReportFrequency: 1m
imageMinimumGCAge: 2m
imageGCHighThresholdPercent: 85
imageGCLowThresholdPercent: 80
volumeStatsAggPeriod: 1m
kubeletCgroups: ""
systemCgroups: ""
cgroupRoot: ""
cgroupsPerQOS: true
cgroupDriver: systemd
runtimeRequestTimeout: 10m
hairpinMode: promiscuous-bridge
maxPods: 220
podCIDR: "${CLUSTER_CIDR}"
podPidsLimit: -1
resolvConf: /etc/resolv.conf
maxOpenFiles: 1000000
kubeAPIQPS: 1000
kubeAPIBurst: 2000
serializeImagePulls: false
evictionHard:
  memory.available:  "100Mi"
nodefs.available:  "10%"
nodefs.inodesFree: "5%"
imagefs.available: "15%"
evictionSoft: {}
enableControllerAttachDetach: true
failSwapOn: true
containerLogMaxSize: 20Mi
containerLogMaxFiles: 10
systemReserved: {}
kubeReserved: {}
systemReservedCgroup: ""
kubeReservedCgroup: ""
enforceNodeAllocatable: ["pods"]
EOF
```
###为各个节点创建和分发kubelet配置文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do 
    echo ">>> ${node_ip}"
    sed -e "s/##NODE_IP##/${node_ip}/" kubelet-config.yaml.template > kubelet-config-${node_ip}.yaml.template
    scp kubelet-config-${node_ip}.yaml.template root@${node_ip}:/etc/kubernetes/kubelet-config.yaml
  done
```

###创建和分发kubelet启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > kubelet.service.template <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service
[Service]
WorkingDirectory=${K8S_DIR}/kubelet
ExecStart=/opt/k8s/bin/kubelet \\
  --allow-privileged=true \\
  --bootstrap-kubeconfig=/etc/kubernetes/kubelet-bootstrap.kubeconfig \\
  --cert-dir=/etc/kubernetes/cert \\
  --cni-conf-dir=/etc/cni/net.d \\
  --container-runtime=docker \\
  --container-runtime-endpoint=unix:///var/run/dockershim.sock \\
  --root-dir=${K8S_DIR}/kubelet \\
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \\
  --config=/etc/kubernetes/kubelet-config.yaml \\
  --hostname-override=##NODE_NAME## \\
  --pod-infra-container-image=gcr.azk8s.cn/google_containers/pause-amd64:3.1 \\
  --image-pull-progress-deadline=15m \\
  --volume-plugin-dir=${K8S_DIR}/kubelet/kubelet-plugins/volume/exec/ \\
  --logtostderr=true \\
  --v=2
Restart=always
RestartSec=5
StartLimitInterval=0
[Install]
WantedBy=multi-user.target
EOF
```
###分发启动文件
```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_name in ${NODE_NAMES[@]}
  do 
    echo ">>> ${node_name}"
    sed -e "s/##NODE_NAME##/${node_name}/" kubelet.service.template > kubelet-${node_name}.service
    scp kubelet-${node_name}.service root@${node_name}:/etc/systemd/system/kubelet.service
  done


Bootstrap Token Auth 和授予权限 kubelet 启动时查找 --kubeletconfig
参数对应的文件是否存在，如果不存在则使用 --bootstrap-kubeconfig 指定的 kubeconfig 文件向
kube-apiserver 发送证书签名请求 (CSR)。 kube-apiserver 收到 CSR 请求后，对其中的 Token
进行认证，认证通过后将请求的 user 设置为 system:bootstrap:，group 设置为
system:bootstrappers，这一过程称为 Bootstrap Token Auth。
```
###创建user和group的CSR权限，不创建kubelet会启动失败
```
kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --group=system:bootstrappers
```
###启动 kubelet 服务
```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kubelet/kubelet-plugins/volume/exec/"
    ssh root@${node_ip} "/usr/sbin/swapoff -a"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kubelet && systemctl restart kubelet"
  done
```
```
关闭 swap 分区，否则 kubelet 会启动失败；
kubelet 启动后使用 –bootstrap-kubeconfig 向 kube-apiserver 发送 CSR 请求，当这个
CSR 被 approve 后，kube-controller-manager 为 kubelet 创建 TLS 客户端证书、私钥和
–kubeletconfig 文件。 注意：kube-controller-manager 需要配置 –cluster-signing-cert-file 和 –cluster-signing-key-file 参数，才会为 TLS Bootstrap 创建证书和私钥。  
 kubectl get csr    
然后会发现好多pending (正在加载中)
```
###自动approve CSR请求
```
创建三个ClusterRoleBinding，分别用于自动approve client、renew client、renew server证书

cd /opt/k8s/work
cat > csr-crb.yaml <<EOF
 # Approve all CSRs for the group "system:bootstrappers"
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: auto-approve-csrs-for-group
 subjects:
 - kind: Group
   name: system:bootstrappers
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:nodeclient
   apiGroup: rbac.authorization.k8s.io
---
 # To let a node of the group "system:nodes" renew its own credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-client-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:selfnodeclient
   apiGroup: rbac.authorization.k8s.io
---
# A ClusterRole which instructs the CSR approver to approve a node requesting a
# serving cert matching its client cert.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: approve-node-server-renewal-csr
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests/selfnodeserver"]
  verbs: ["create"]
---
 # To let a node of the group "system:nodes" renew its own server credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-server-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: approve-node-server-renewal-csr
   apiGroup: rbac.authorization.k8s.io
EOF
kubectl apply -f csr-crb.yaml
```
###查看kubelet
```
等待1-10分钟，3个节点的CSR都会自动approved
kubectl get csr
```
```
kubectl get csr | head -10
NAME        AGE   REQUESTOR                 CONDITION
csr-24frb   40m   system:bootstrap:zfcoqb   Approved,Issued
csr-24rtq   63m   system:bootstrap:zfcoqb   Approved,Issued
csr-25m98   74m   system:bootstrap:k555eq   Approved,Issued
csr-26c64   58m   system:bootstrap:k555eq   Approved,Issued
csr-26wbs   50m   system:bootstrap:arc548   Approved,Issued
csr-27fp4   34m   system:bootstrap:eg8wj5   Approved,Issued
csr-28pgw   59m   system:bootstrap:eg8wj5   Approved,Issued
csr-2bq87   57m   system:bootstrap:arc548   Approved,Issued
csr-2cvlq   36m   system:bootstrap:arc548   Approved,Issued
```
###Pending的CSR用于创建kubelet serve证书，需要手动approve (后面步骤)
```
目前所有节点均为ready状态
[root@abcdocker-k8s01 work]# kubectl get node
NAME     STATUS   ROLES    AGE     VERSION
k8s-01   Ready       2m29s   v1.14.2
k8s-02   Ready       2m28s   v1.14.2
k8s-03   Ready       2m28s   v1.14.2
k8s-04   Ready       2m27s   v1.14.2
```

###因出现kubectl get node  No resources found. ###需要重新分析步骤,到这里停止
_________________________________________________________
查看报错
```
3月 05 18:27:08 k8s-01 kubelet[124075]: F0305 18:27:08.503116  124075 server.go:265] failed to run Kubelet: failed to create kubelet: misconfiguration: kubelet cgroup driver: "systemd" is different from docker cgroup driver: "cgroupfs"
```
```
mkdir -p /etc/docker
cat > /etc/docker/daemon.json  << EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "registry-mirrors": ["https://hjvrgh7a.mirror.aliyuncs.com"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF
systemctl daemon-reload  #加载配置文件
systemctl restart docker     #重启docker
systemctl restart kubelet    #重启kubelet
systemctl status kubelet     #查看kubelet状态
```
_____________________________________________________________
###手动approve server cert csr
```
基于安全考虑，CSR approving controllers不会自动approve kubelet server证书签名请求，需要手动approve
kubectl get csr | grep Pending | awk '{print $1}' | xargs kubectl certificate approve
```
```
kubectl get csr | grep Pending | awk '{print $1}' | xargs kubectl certificate approve
certificatesigningrequest.certificates.k8s.io/csr-ltf7g approved
certificatesigningrequest.certificates.k8s.io/csr-p7ltq approved
certificatesigningrequest.certificates.k8s.io/csr-pvf82 approved
certificatesigningrequest.certificates.k8s.io/csr-pw56z approved
certificatesigningrequest.certificates.k8s.io/csr-srwvr approved
certificatesigningrequest.certificates.k8s.io/csr-w6r7c approved
certificatesigningrequest.certificates.k8s.io/csr-whbzb approved
certificatesigningrequest.certificates.k8s.io/csr-x75r4 approved
```