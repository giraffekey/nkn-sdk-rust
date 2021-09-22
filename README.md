# nkn-sdk-rust

[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/giraffekey/nkn-sdk-rust/blob/master/LICENSE)

Rust implementation of NKN client and wallet SDK. The SDK consists of a
few components:

- [NKN Client](#client): Send and receive data for free between any NKN clients
  regardless their network condition without setting up a server or relying on
  any third party services. Data are end to end encrypted by default. Typically
  you might want to use [multiclient](#multiclient) instead of using client
  directly.

- [NKN MultiClient](#multiclient): Send and receive data using multiple NKN
  clients concurrently to improve reliability and latency. In addition, it
  supports session mode, a reliable streaming protocol similar to TCP based
  on [ncp](https://github.com/giraffekey/ncp-rust).

- [NKN Wallet](#wallet): Wallet SDK for [NKN
  blockchain](https://github.com/nknorg/nkn). It can be used to create wallet,
  transfer token to NKN wallet address, register name, subscribe to topic,
  etc.

Advantages of using NKN client/multiclient for data transmission:

- Network agnostic: Neither sender nor receiver needs to have public IP address
  or port forwarding. NKN clients only establish outbound (websocket)
  connections, so Internet access is all they need. This is ideal for client
  side peer to peer communication.

- Top level security: All data are end to end authenticated and encrypted. No
  one else in the world except sender and receiver can see or modify the content
  of the data. The same public key is used for both routing and encryption,
  eliminating the possibility of man in the middle attack.

- Decent performance: By aggregating multiple overlay paths concurrently,
  multiclient can get ~100ms end to end latency and 10+mbps end to end session
  throughput between international devices.

- Everything is free, open source and decentralized. (If you are curious, node
  relay traffic for clients for free to earn mining rewards in NKN blockchain.)

## Documentation

Not created yet.

## Usage

### Client

NKN Client provides low level p2p messaging through NKN network. For most
applications, it's more suitable to use multiclient (see
[multiclient](#multiclient) section below) for better reliability, lower
latency, and session mode support.

Create a client with a generated key pair:

```rust
let mut rng = thread_rng();
let account = Account::new_random(&mut rng).unwrap();
let client = Client::new(account, None, ClientConfig::default());
```

Or with an identifier (used to distinguish different clients sharing the same
key pair):

```rust
let client = Client::new(account, Some("identifier"), ClientConfig::default());
```

Get client key pair:

```rust
println!("{:?}{:?}", account.seed(), account.public_key());
```

Create a client using an existing secret seed:

```rust
let seed = hex::decode("039e481266e5a05168c1d834a94db512dbc235877f150c5a3cc1e3903672c673").unwrap();
let account = Account::new(seed).unwrap();
let client = Client::new(&account, Some("identifier"), ClientConfig::default());
```

Secret seed should be kept **SECRET**! Never put it in version control system
like here.

By default the client will use bootstrap RPC server (for getting node address)
provided by NKN. Any NKN full node can serve as a bootstrap RPC server. To
create a client using customized bootstrap RPC server:

```rust
let config = ClientConfig {
	rpc_server_address: vec!["https://ip:port", "https://ip2:port2"],
	..ClientConfig::default()
};
let client = Client::new(&account, Some("identifier"), config);
```

Get client NKN address, which is used to receive data from other clients:

```rust
println!("{:?}", client.address());
```

Listen for connection established:

```rust
client.wait_for_connect();
println!("Connection opened.");
```

Send text message to other clients:

```rust
client.send(&["another client address"], "hello world!".as_bytes(), MessageConfig::default());
```

You can also send byte array directly:

```rust
client.send(&["another client address"], &[1u8, 2u8, 3u8, 4u8, 5u8], MessageConfig::default());
```

Or publish a message to a specified topic (see wallet section for subscribing to
topics):

```rust
client.publish("topic", "hello world!".as_bytes(), MessageConfig::default());
```

Receive data from other clients:

```rust
let msg = client.wait_for_message();
println!("Receive message from {:?}: {:?}", msg.source(), msg.data());
msg.reply("response".as_bytes());
```

Get 100 subscribers of specified topic starting from 0 offset, including those
in tx pool (fetch meta):

```rust
let subscribers = client.subscribers("topic", 0, 100, true, true);
println!("{:?} {:?}", subscribers.map(), subscribers.tx_pool_map());
```

Get subscription:

```rust
let subscription = client.subscription("topic", "identifier.publickey");
println!("{:?}", subscription);
```

### Multiclient

Multiclient creates multiple client instances by adding identifier prefix
(`__0__.`, `__1__.`, `__2__.`, ...) to a nkn address and send/receive packets
concurrently. This will greatly increase reliability and reduce latency at the
cost of more bandwidth usage (proportional to the number of clients).

Multiclient basically has the same API as client, except for a few more
initial configurations:

```rust
let num_sub_clients = 3;
let original_client = false;
let multiclient = MultiClient::new(&account, identifier, numSubClient, originalClient);
```

where `original_client` controls whether a client with original identifier
(without adding any additional identifier prefix) will be created, and
`num_sub_clients` controls how many sub-clients to create by adding prefix
`__0__.`, `__1__.`, `__2__.`, etc. Using `original_client == true` and
`num_sub_clients == 0` is equivalent to using a standard client without any
modification to the identifier. Note that if you use `original_client == true`
and `num_sub_clients` is greater than 0, your identifier should not starts with
`__X__` where `X` is any number, otherwise you may end up with identifier
collision.

Any additional options will be passed to NKN client.

### Session

Multiclient supports a reliable transmit protocol called session. It will be
responsible for retransmission and ordering just like TCP. It uses multiple
clients to send and receive data in multiple path to achieve better throughput.
Unlike regular multiclient message, no redundant data is sent unless packet
loss.

Any multiclient can start listening for incoming session where the remote
address match any of the given regexp:

```rust
let multiclient = MultiClient::new(...);
// Accepting any address, equivalent to multiclient.listen(&[".*"])
multiclient.listen(&[]);
// Only accepting pubkey 25d660916021ab1d182fb6b52d666b47a0f181ed68cf52a056041bdcf4faaf99 but with any identifiers
multiclient.listen(&["25d660916021ab1d182fb6b52d666b47a0f181ed68cf52a056041bdcf4faaf99$"]);
// Only accepting address alice.25d660916021ab1d182fb6b52d666b47a0f181ed68cf52a056041bdcf4faaf99
multiclient.listen(&["^alice\\.25d660916021ab1d182fb6b52d666b47a0f181ed68cf52a056041bdcf4faaf99$"]);
```

Then it can start accepting sessions:

```rust
let session = multiclient.accept();
```

On the other hand, any multiclient can dial a session to a remote NKN address:

```rust
let session = multiclient.dial("another nkn address");
```

Read and write to session:

```rust
let data = session.read();
let buf = [0u8; 1024];
session.write(&buf);
```

### Wallet

Create wallet SDK:

```rust
let mut rng = thread_rng();
let account = Account::new_random(&mut rng).unwrap();
let config = WalletConfig {
	password: "password".into(),
	..WalletConfig::default()
};
let wallet = Wallet::new(&account, config);
```

By default the wallet will use RPC server provided by `nkn.org`. Any NKN full
node can serve as a RPC server. To create a wallet using customized RPC server:

```rust
let config = WalletConfig {
	password: "password".into(),
	rpc_server_address: vec!["https://ip:port", "https://ip2:port2"],
	..WalletConfig::default()
};
let wallet = Wallet::new(&account, config);
```

Export wallet to JSON string, where sensitive contents are encrypted by password
provided in config:

```rust
let wallet_json = wallet.to_json();
```

Load wallet from JSON string, note that the password needs to be the same as the
one provided when creating wallet:

```rust
let config = WalletConfig {
	password: "password".into(),
	..WalletConfig::default()
};
let wallet = Wallet::from_json(wallet_json, config);
```

Verify whether an address is a valid NKN wallet address:

```rust
let is_valid = Wallet::verify_wallet_address(wallet.address());
```

Verify password of the wallet:

```rust
let is_valid = wallet.verify_password("password");
```

Query asset balance for this wallet:

```rust
let balance = wallet.balance();
```

Query asset balance for address:

```rust
let balance = wallet.balance_by_address("NKNxxxxx");
```

Transfer asset to some address:

```rust
let tx_hash = wallet.transfer(account.wallet_address(), string_to_amount("100"), TransactionConfig::default());
```

Open nano pay channel to specified address:

```rust
// you can pass channel duration (in unit of blocks) after address and txn fee
// after expired new channel (with new id) will be created under-the-hood
// this means that receiver need to claim old channel and reset amount calculation
let np = wallet.create_nano_pay(address, string_to_amount("0"), 4320);
```

Increment channel balance by 100 NKN:

```rust
let tx = np.increment_amount(string_to_amount("100"));
```

Then you can pass the transaction to receiver, who can send transaction to
on-chain later:

```rust
let tx_hash = wallet.send_raw_transaction(tx);
```

Register name for this wallet:

```rust
let tx_hash = wallet.register_name("somename", TransactionConfig::default());
```

Delete name for this wallet:

```rust
let tx_hash = wallet.delete_name("somename", TransactionConfig::default());
```

Subscribe to specified topic for this wallet for next 100 blocks:

```rust
let tx_hash = wallet.subscribe("identifier", "topic", 100, "meta", TransactionConfig::default());
```

Unsubscribe from specified topic:

```rust
let tx_hash = wallet.unsubscribe("identifier", "topic", TransactionConfig::default());
```

## Contributing

**Can I submit a bug, suggestion or feature request?**

Yes. Please open an issue for that.

**Can I contribute patches?**

Yes, we appreciate your help! To make contributions, please fork the repo, push
your changes to the forked repo with signed-off commits, and open a pull request
here.

Please sign off your commit. This means adding a line "Signed-off-by: Name
<email>" at the end of each commit, indicating that you wrote the code and have
the right to pass it on as an open source patch. This can be done automatically
by adding -s when committing:

```shell
git commit -s
```

## Community

- [Forum](https://forum.nkn.org/)
- [Discord](https://discord.gg/c7mTynX)
- [Telegram](https://t.me/nknorg)
- [Reddit](https://www.reddit.com/r/nknblockchain/)
- [Twitter](https://twitter.com/NKN_ORG)
