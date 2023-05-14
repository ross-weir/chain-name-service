## Notes

## TODO

- Fees for contract developer & ui developer when minting a Resolver
- Stable pricing using oracle USD price feed
- Scalability - only one name can be minted per tx (per block i think?)

## Maybe

- SubResolvers, to allow the owner of `myname.erg` to mint `pay.myname.erg`, etc

## Testing

TODO: setup test fixtures so all test cases use exactly the same tx as the success case except for the aspect under test
This is the current setup but copy+pasted for each test, use fixtures

### `NewRegistrar.es`

- [x] fail if RegistryAdmin data input is missing
- [x] fail if RegistryAdmin data input has incorrect nft
- [x] fail if registrar already exists
- [x] fail if registrars state in Registry isn't updated correctly (AVL digest mismatch)
- [ ] fail if successor box propBytes changed or nft changed
- [x] add new registrar to Registry

### `Resolver.es`

- [x] label preserved
- [x] tld preserved
- [x] nft preserved
- [x] script preserved
