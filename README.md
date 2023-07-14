# Building custom DNS server in Rust

- Following this [guide](https://github.com/EmilHernvall/dnsguide) started
  writing DNS server for myself.
- Following this series
  [started](https://fasterthanli.me/series/making-our-own-ping) refactoring to
  more pleasant parsing and serialization.

# Usage
In one shell
```shell
./target/debug/custom-dns-server
```

In another shell

```shell
dig @127.0.0.1 -p 2053 www.google.com
```



