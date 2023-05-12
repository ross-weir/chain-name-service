## Notes

- We could allow only submitting hashed names for better anon - chain observers couldn't see what name was used for resolution but then couldn't check for illegal characters
  - Should we have illegal characters or allow everything?

## TODO

- `NewRegistrar` admin check needs to be validated, if anyone can use a box belonging to anyone as a data input it wont work
- Fees for contract developer & ui developer when minting a Resolver
- Stable pricing using oracle USD price feed
- Scalability - only one name can be minted per tx (per block i think?)

## Maybe

- SubResolvers, to allow the owner of `myname.erg` to mint `pay.myname.erg`, etc

## Testing

TODO: setup test fixtures so all test cases use exactly the same tx as the success case except for the aspect under test

### `NewRegistrar.es`

- [x] fail if RegistryAdmin data input is missing
- [x] fail if RegistryAdmin data input has incorrect nft
- [x] fail if registrar already exists
- [x] fail if registrars state in Registry isn't updated correctly (AVL digest mismatch)
- [ ] fail if successor box propBytes changed or nft changed
- [x] add new registrar to Registry

### `MintResolver.es`

- [x] fail if `tld` doesn't exist in registrars AVL tree
- [x] fail if `label` is invalid (TODO what is a "valid" label)
- [x] ensure `Resolver` out box
  - [x] fail if propBytes != `Resolver.es`
  - [x] fail if in-box `label` mismatch
  - [x] fail if in-box `tld` mismatch
  - [x] fail if in-box `address` mismatch
  - [x] contains nft
- [ ] fail if invalid funds paid (TODO determine "valid" payment)
- [x] fail if successor propBytes or tokens changed
- [x] mints resolver box

### `Resolver.es`

- [ ] label preserved
- [ ] tld preserved
- [ ] nft preserved
- [ ] script preserved
