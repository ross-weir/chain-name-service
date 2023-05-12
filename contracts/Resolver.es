{
  // Resolver script
  //
  // NOTES
  //
  // design this so it can be applied recursively?
  // name.erg -> pay.name.erg -> another.pay.name.erg etc?
  //
  // TRANSACTIONS
  //
  // [1] Update resolution address
  // To update the address that this resolver resolves to simply send the box to yourself with everything
  // preserved except R6 updated.
  //
  // The value of R6 should be the address including network encoding, for
  // example on ergo: 3WwhifgHTu7ib5ggKKVFaN1J6jFim3u9siPspDRq9JnwcKfLuuxc
  //
  // Or if the resolver is for Cardano: addr1qyht4ja0zcn45qvyx477qlyp6j5ftu5ng0prt9608dxp6l2j2c79gy9l76sdg0xwhd7r0c0kna0tycz4y5s6mlenh8pq4jxtdy
  //
  //   Input         |  Output        |  Data-Input
  // -----------------------------------------------
  // 0 Resolver      |  Resolver      |
  //
  // [2] Transfer ownership
  // To transfer ownership simply send the box to its new owners address.
  //
  // The new owner should ensure the resolver address is updated accordly otherwise funds
  // will continue to go to the previous owner.
  //
  //   Input         |  Output        |  Data-Input
  // -----------------------------------------------
  // 0 Resolver      |  Resolver      |
  //
  // REGISTERS
  //  R4: CONST (Coll[Byte]) Label (name) that is used to resolve an address.
  //  R5: CONST (Coll[Byte]) Registrar/TLD, "erg" for example.
  //  R6: MUT   (Coll[Byte]) Address to resolve to, this should be set based on the TLD.
  //                   For example if TLD is "erg" an Ergo address, if TLD is "ada" a Cardano address.

  val successor = OUTPUTS(0)

  val currentLabel = SELF.R4[Coll[Byte]].get
  val currentTld = SELF.R5[Coll[Byte]].get
  val currentNft = SELF.tokens(0)

  // label unchanged
  val validLabel = currentLabel == successor.R4[Coll[Byte]].get
  // tld unchanged
  val validTld = currentTld == successor.R5[Coll[Byte]].get
  // nft unchanged
  val validNft = currentNft == successor.tokens(0)
  // script unchanged
  val validScript = SELF.propositionBytes == successor.propositionBytes

  sigmaProp(
    validLabel &&
    validTld &&
    validNft &&
    validScript
  )
}