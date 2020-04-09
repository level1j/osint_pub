# OSINT tools

## Requirements

### python3

You need Python 3.
Also you may need Python 3.6 or later.

### packages

* firefox-geckodriver
* git
* golang
* netcat-traditional
* nmap
* python3-pip
* whois

### python packages

* beautifulsoup4
* defang
* dnspython
* lxml
* python-dateutil
* python-whois
* selenium
* tldextract

## Installation

To install packages

```
$ sudo apt install firefox-geckodriver git golang netcat-traditional nmap python3-pip whois
```

To install python packages

```
pip3 install -r requirements.txt
```

To install rdap

see [https://github.com/openrdap/rdap]

```
$ go get -u github.com/openrdap/rdap/cmd/rdap
$ echo 'export GOPATH=/home/<user>/go' >> ~/.bashrc
$ echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
$ source ~/.bashrc
```

## Usage

1. web_preserve.py

Execute ip2as_cymru, whois_domain, rdap_wrapper, ssl_wrapper, screenshot and dirlist4wgetlog

```
$ ./web_preserve.py --help
usage: web_preserve.py [-h] [-u URLS] [-f URL_FILE] [--no-nmap]

Execute ip2as,whois_domain,rdap_wrapper,ssl_wrapper,screenshot

optional arguments:
  -h, --help		show this help message and exit
  -u URLS, --url URLS		url1[,url2]
  -f URL_FILE, --file URL_FILE		url list file
  --no-nmap		disable nmap
```


2. ip2as_cymru.py

```

$ ./ip2as_cymru.py --help
usage: ip2as_cymru.py [-h] [-i IPS] [-f IP_FILE] [-t] [-j]

optional arguments:
  -h, --help		show this help message and exit
  -i IPS, --ip IPS		ip1[,ip2]
  -f IP_FILE, --file IP_FILE		ip list file
  -t, --tsv		output tsv
  -j, --json		output json
```


3. whois_domain.py

```
$ ./whois_domain.py --help
usage: whois_domain.py [-h] [-d DOMAINS] [-f DOMAIN_FILE] [-t] [-j]

optional arguments:
  -h, --help		show this help message and exit
  -d DOMAINS, --domain DOMAINS		domain1[,domain2]
  -f DOMAIN_FILE, --file DOMAIN_FILE		domain list file
  -t, --tsv		output tsv
  -j, --json		output json
```

4. rdap_wrapper.py

```
$ ./rdap_wrapper.py --help
usage: rdap_wrapper.py [-h] [-d DOMAINS] [-f DOMAIN_FILE] [-r RDAP_JSON_FILE] [-t] [-j]

optional arguments:
  -h, --help		show this help message and exit
  -d DOMAINS, --domain DOMAINS		domain1[,domain2]
  -f DOMAIN_FILE, --file DOMAIN_FILE		domain list file
  -r RDAP_JSON_FILE, --rdap RDAP_JSON_FILE		rdap json file
  -t, --tsv		output tsv
  -j, --json		output json
```

5. ssl_wrapper.py

```
$ ./ssl_wrapper.py --help
usage: ssl_wrapper.py [-h] [-s SERVERNAME] [-c CERT_FILE] [-t] [-j]

optional arguments:
  -h, --help		show this help message and exit
  -s SERVERNAME, --servername SERVERNAME		servername
  -c CERT_FILE, --cert CERT_FILE		cert file
  -t, --tsv		output tsv
  -j, --json		output json
```

6. screenshot.py

```
$ ./screenshot.py --help
usage: screenshot.py [-h] [--up USERAGENT_PC] [--us USERAGENT_SMARTPHONE] [-p] [-s] [--save-html] [--http-https] url

take screenshot

positional arguments:
  url			URL

optional arguments:
  -h, --help		show this help message and exit
  --up USERAGENT_PC, --useragent-pc USERAGENT_PC		User-Agent for pc mode
  --us USERAGENT_SMARTPHONE, --useragent-smartphone USERAGENT_SMARTPHONE		User-Agent for smartphone mode
  -p, --pc		pc mode
  -s, --smartphone	smart phone mode
  --save-html		save html
  --http-https		screenshot with both http and https
```

7. dirlist4wgetlog.py

```
$ ./dirlist4wgetlog.py --help
usage: dirlist4wgetlog.py [-h] [-w WGET_LOG_LIST] [-d WGET_LOG_DIR_LIST]
			  domain_list

positional arguments:
  domain_list		domain,domain2,...

optional arguments:
  -h, --help		show this help message and exit
  -w WGET_LOG_LIST, --wget-log WGET_LOG_LIST
			wget log file,wget log file2,...
  -d WGET_LOG_DIR_LIST, --wget-log-dir WGET_LOG_DIR_LIST
			dir(contains wget log file.),dir2,...
```
